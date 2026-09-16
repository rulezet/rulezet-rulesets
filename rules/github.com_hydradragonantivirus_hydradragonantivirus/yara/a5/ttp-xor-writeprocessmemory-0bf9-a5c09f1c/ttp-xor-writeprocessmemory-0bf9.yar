rule TTP_XOR_WriteProcessMemory_0bf9 {
  strings:
    $key_0bf9 = { 5c 8b [2] 6e a9 [2] 68 9c [2] 46 9c [2] 79 80 }

  condition:
    any of them
}