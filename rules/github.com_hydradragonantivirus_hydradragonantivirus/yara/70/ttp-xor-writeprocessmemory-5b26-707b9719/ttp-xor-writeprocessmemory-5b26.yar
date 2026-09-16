rule TTP_XOR_WriteProcessMemory_5b26 {
  strings:
    $key_5b26 = { 0c 54 [2] 3e 76 [2] 38 43 [2] 16 43 [2] 29 5f }

  condition:
    any of them
}