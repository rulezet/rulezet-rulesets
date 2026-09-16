rule TTP_XOR_WriteProcessMemory_4729 {
  strings:
    $key_4729 = { 10 5b [2] 22 79 [2] 24 4c [2] 0a 4c [2] 35 50 }

  condition:
    any of them
}