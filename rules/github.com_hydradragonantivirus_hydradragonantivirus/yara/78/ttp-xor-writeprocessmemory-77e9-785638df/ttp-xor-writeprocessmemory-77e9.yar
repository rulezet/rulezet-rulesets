rule TTP_XOR_WriteProcessMemory_77e9 {
  strings:
    $key_77e9 = { 20 9b [2] 12 b9 [2] 14 8c [2] 3a 8c [2] 05 90 }

  condition:
    any of them
}