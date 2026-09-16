rule TTP_XOR_WriteProcessMemory_1e29 {
  strings:
    $key_1e29 = { 49 5b [2] 7b 79 [2] 7d 4c [2] 53 4c [2] 6c 50 }

  condition:
    any of them
}