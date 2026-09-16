rule TTP_XOR_WriteProcessMemory_39f2 {
  strings:
    $key_39f2 = { 6e 80 [2] 5c a2 [2] 5a 97 [2] 74 97 [2] 4b 8b }

  condition:
    any of them
}