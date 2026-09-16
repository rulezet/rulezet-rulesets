rule TTP_XOR_WriteProcessMemory_5c26 {
  strings:
    $key_5c26 = { 0b 54 [2] 39 76 [2] 3f 43 [2] 11 43 [2] 2e 5f }

  condition:
    any of them
}