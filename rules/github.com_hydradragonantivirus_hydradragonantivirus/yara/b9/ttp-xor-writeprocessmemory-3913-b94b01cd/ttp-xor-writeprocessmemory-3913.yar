rule TTP_XOR_WriteProcessMemory_3913 {
  strings:
    $key_3913 = { 6e 61 [2] 5c 43 [2] 5a 76 [2] 74 76 [2] 4b 6a }

  condition:
    any of them
}