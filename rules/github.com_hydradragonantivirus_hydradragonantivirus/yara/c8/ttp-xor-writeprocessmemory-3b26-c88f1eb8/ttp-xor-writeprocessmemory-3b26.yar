rule TTP_XOR_WriteProcessMemory_3b26 {
  strings:
    $key_3b26 = { 6c 54 [2] 5e 76 [2] 58 43 [2] 76 43 [2] 49 5f }

  condition:
    any of them
}