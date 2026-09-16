rule TTP_XOR_WriteProcessMemory_39f8 {
  strings:
    $key_39f8 = { 6e 8a [2] 5c a8 [2] 5a 9d [2] 74 9d [2] 4b 81 }

  condition:
    any of them
}