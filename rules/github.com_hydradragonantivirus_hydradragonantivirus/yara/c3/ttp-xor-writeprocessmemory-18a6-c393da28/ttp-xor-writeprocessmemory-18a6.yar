rule TTP_XOR_WriteProcessMemory_18a6 {
  strings:
    $key_18a6 = { 4f d4 [2] 7d f6 [2] 7b c3 [2] 55 c3 [2] 6a df }

  condition:
    any of them
}