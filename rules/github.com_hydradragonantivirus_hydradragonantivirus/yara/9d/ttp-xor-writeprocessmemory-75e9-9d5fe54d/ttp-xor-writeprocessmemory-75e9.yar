rule TTP_XOR_WriteProcessMemory_75e9 {
  strings:
    $key_75e9 = { 22 9b [2] 10 b9 [2] 16 8c [2] 38 8c [2] 07 90 }

  condition:
    any of them
}