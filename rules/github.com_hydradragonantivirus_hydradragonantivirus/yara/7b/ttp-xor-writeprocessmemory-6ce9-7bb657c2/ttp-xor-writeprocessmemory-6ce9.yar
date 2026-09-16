rule TTP_XOR_WriteProcessMemory_6ce9 {
  strings:
    $key_6ce9 = { 3b 9b [2] 09 b9 [2] 0f 8c [2] 21 8c [2] 1e 90 }

  condition:
    any of them
}