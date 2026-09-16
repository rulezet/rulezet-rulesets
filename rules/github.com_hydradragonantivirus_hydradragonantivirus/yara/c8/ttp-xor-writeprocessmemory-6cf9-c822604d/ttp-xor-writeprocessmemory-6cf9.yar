rule TTP_XOR_WriteProcessMemory_6cf9 {
  strings:
    $key_6cf9 = { 3b 8b [2] 09 a9 [2] 0f 9c [2] 21 9c [2] 1e 80 }

  condition:
    any of them
}