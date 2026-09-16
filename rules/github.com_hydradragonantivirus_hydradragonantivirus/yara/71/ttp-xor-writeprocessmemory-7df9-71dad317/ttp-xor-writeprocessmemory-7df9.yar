rule TTP_XOR_WriteProcessMemory_7df9 {
  strings:
    $key_7df9 = { 2a 8b [2] 18 a9 [2] 1e 9c [2] 30 9c [2] 0f 80 }

  condition:
    any of them
}