rule TTP_XOR_WriteProcessMemory_39c3 {
  strings:
    $key_39c3 = { 6e b1 [2] 5c 93 [2] 5a a6 [2] 74 a6 [2] 4b ba }

  condition:
    any of them
}