rule TTP_XOR_WriteProcessMemory_e3d4 {
  strings:
    $key_e3d4 = { b4 a6 [2] 86 84 [2] 80 b1 [2] ae b1 [2] 91 ad }

  condition:
    any of them
}