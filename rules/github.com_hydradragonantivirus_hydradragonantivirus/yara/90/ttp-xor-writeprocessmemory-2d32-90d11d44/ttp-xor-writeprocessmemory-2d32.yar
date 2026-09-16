rule TTP_XOR_WriteProcessMemory_2d32 {
  strings:
    $key_2d32 = { 7a 40 [2] 48 62 [2] 4e 57 [2] 60 57 [2] 5f 4b }

  condition:
    any of them
}