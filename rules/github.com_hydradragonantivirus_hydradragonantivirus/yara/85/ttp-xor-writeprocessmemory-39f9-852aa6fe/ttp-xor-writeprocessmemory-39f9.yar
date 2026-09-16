rule TTP_XOR_WriteProcessMemory_39f9 {
  strings:
    $key_39f9 = { 6e 8b [2] 5c a9 [2] 5a 9c [2] 74 9c [2] 4b 80 }

  condition:
    any of them
}