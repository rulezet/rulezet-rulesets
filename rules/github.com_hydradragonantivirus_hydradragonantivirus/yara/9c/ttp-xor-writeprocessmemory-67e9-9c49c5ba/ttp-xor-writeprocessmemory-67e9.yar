rule TTP_XOR_WriteProcessMemory_67e9 {
  strings:
    $key_67e9 = { 30 9b [2] 02 b9 [2] 04 8c [2] 2a 8c [2] 15 90 }

  condition:
    any of them
}