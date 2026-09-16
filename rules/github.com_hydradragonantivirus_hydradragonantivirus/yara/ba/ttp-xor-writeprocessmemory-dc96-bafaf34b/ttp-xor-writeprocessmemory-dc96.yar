rule TTP_XOR_WriteProcessMemory_dc96 {
  strings:
    $key_dc96 = { 8b e4 [2] b9 c6 [2] bf f3 [2] 91 f3 [2] ae ef }

  condition:
    any of them
}