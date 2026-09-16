rule TTP_XOR_WriteProcessMemory_2569 {
  strings:
    $key_2569 = { 72 1b [2] 40 39 [2] 46 0c [2] 68 0c [2] 57 10 }

  condition:
    any of them
}