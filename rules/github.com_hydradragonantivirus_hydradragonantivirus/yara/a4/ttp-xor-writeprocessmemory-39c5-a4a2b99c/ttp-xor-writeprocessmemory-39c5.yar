rule TTP_XOR_WriteProcessMemory_39c5 {
  strings:
    $key_39c5 = { 6e b7 [2] 5c 95 [2] 5a a0 [2] 74 a0 [2] 4b bc }

  condition:
    any of them
}