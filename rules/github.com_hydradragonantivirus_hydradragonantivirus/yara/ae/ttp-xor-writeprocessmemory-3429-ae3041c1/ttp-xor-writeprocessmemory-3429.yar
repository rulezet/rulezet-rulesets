rule TTP_XOR_WriteProcessMemory_3429 {
  strings:
    $key_3429 = { 63 5b [2] 51 79 [2] 57 4c [2] 79 4c [2] 46 50 }

  condition:
    any of them
}