rule TTP_XOR_WriteProcessMemory_44e9 {
  strings:
    $key_44e9 = { 13 9b [2] 21 b9 [2] 27 8c [2] 09 8c [2] 36 90 }

  condition:
    any of them
}