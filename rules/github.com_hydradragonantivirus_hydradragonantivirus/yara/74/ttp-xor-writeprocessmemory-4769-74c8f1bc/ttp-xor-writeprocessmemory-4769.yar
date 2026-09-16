rule TTP_XOR_WriteProcessMemory_4769 {
  strings:
    $key_4769 = { 10 1b [2] 22 39 [2] 24 0c [2] 0a 0c [2] 35 10 }

  condition:
    any of them
}