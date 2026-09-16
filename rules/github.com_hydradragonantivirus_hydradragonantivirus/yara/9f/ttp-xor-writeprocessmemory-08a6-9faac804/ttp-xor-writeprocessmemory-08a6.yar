rule TTP_XOR_WriteProcessMemory_08a6 {
  strings:
    $key_08a6 = { 5f d4 [2] 6d f6 [2] 6b c3 [2] 45 c3 [2] 7a df }

  condition:
    any of them
}