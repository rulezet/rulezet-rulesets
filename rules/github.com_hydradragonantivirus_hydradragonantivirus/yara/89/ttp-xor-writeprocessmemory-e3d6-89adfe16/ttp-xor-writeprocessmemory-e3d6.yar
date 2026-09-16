rule TTP_XOR_WriteProcessMemory_e3d6 {
  strings:
    $key_e3d6 = { b4 a4 [2] 86 86 [2] 80 b3 [2] ae b3 [2] 91 af }

  condition:
    any of them
}