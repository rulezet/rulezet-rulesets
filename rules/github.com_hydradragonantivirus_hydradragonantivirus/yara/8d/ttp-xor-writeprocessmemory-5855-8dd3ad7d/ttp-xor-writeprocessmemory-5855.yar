rule TTP_XOR_WriteProcessMemory_5855 {
  strings:
    $key_5855 = { 0f 27 [2] 3d 05 [2] 3b 30 [2] 15 30 [2] 2a 2c }

  condition:
    any of them
}