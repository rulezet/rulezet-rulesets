rule TTP_XOR_WriteProcessMemory_39f3 {
  strings:
    $key_39f3 = { 6e 81 [2] 5c a3 [2] 5a 96 [2] 74 96 [2] 4b 8a }

  condition:
    any of them
}