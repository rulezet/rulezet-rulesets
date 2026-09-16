rule TTP_XOR_WriteProcessMemory_3bb1 {
  strings:
    $key_3bb1 = { 6c c3 [2] 5e e1 [2] 58 d4 [2] 76 d4 [2] 49 c8 }

  condition:
    any of them
}