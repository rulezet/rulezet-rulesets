rule TTP_XOR_WriteProcessMemory_13e9 {
  strings:
    $key_13e9 = { 44 9b [2] 76 b9 [2] 70 8c [2] 5e 8c [2] 61 90 }

  condition:
    any of them
}