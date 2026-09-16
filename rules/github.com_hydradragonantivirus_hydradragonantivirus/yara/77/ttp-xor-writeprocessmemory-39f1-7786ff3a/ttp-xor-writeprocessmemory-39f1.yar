rule TTP_XOR_WriteProcessMemory_39f1 {
  strings:
    $key_39f1 = { 6e 83 [2] 5c a1 [2] 5a 94 [2] 74 94 [2] 4b 88 }

  condition:
    any of them
}