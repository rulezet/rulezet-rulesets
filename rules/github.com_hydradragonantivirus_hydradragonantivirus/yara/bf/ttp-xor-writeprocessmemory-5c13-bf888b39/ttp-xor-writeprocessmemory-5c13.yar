rule TTP_XOR_WriteProcessMemory_5c13 {
  strings:
    $key_5c13 = { 0b 61 [2] 39 43 [2] 3f 76 [2] 11 76 [2] 2e 6a }

  condition:
    any of them
}