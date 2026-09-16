rule TTP_XOR_WriteProcessMemory_3569 {
  strings:
    $key_3569 = { 62 1b [2] 50 39 [2] 56 0c [2] 78 0c [2] 47 10 }

  condition:
    any of them
}