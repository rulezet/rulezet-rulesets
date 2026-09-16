rule TTP_XOR_WriteProcessMemory_0e29 {
  strings:
    $key_0e29 = { 59 5b [2] 6b 79 [2] 6d 4c [2] 43 4c [2] 7c 50 }

  condition:
    any of them
}