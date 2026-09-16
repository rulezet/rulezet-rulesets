rule TTP_XOR_WriteProcessMemory_5ce9 {
  strings:
    $key_5ce9 = { 0b 9b [2] 39 b9 [2] 3f 8c [2] 11 8c [2] 2e 90 }

  condition:
    any of them
}