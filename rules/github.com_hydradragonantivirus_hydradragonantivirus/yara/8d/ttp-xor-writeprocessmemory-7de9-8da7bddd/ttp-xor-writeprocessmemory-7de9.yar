rule TTP_XOR_WriteProcessMemory_7de9 {
  strings:
    $key_7de9 = { 2a 9b [2] 18 b9 [2] 1e 8c [2] 30 8c [2] 0f 90 }

  condition:
    any of them
}