rule TTP_XOR_WriteProcessMemory_15e9 {
  strings:
    $key_15e9 = { 42 9b [2] 70 b9 [2] 76 8c [2] 58 8c [2] 67 90 }

  condition:
    any of them
}