rule TTP_XOR_WriteProcessMemory_e3d7 {
  strings:
    $key_e3d7 = { b4 a5 [2] 86 87 [2] 80 b2 [2] ae b2 [2] 91 ae }

  condition:
    any of them
}