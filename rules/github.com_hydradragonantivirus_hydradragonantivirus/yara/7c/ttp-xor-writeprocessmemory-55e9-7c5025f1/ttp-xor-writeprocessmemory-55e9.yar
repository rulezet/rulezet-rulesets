rule TTP_XOR_WriteProcessMemory_55e9 {
  strings:
    $key_55e9 = { 02 9b [2] 30 b9 [2] 36 8c [2] 18 8c [2] 27 90 }

  condition:
    any of them
}