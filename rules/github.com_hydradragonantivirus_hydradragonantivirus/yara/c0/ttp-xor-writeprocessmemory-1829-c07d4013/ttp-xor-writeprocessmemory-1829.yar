rule TTP_XOR_WriteProcessMemory_1829 {
  strings:
    $key_1829 = { 4f 5b [2] 7d 79 [2] 7b 4c [2] 55 4c [2] 6a 50 }

  condition:
    any of them
}