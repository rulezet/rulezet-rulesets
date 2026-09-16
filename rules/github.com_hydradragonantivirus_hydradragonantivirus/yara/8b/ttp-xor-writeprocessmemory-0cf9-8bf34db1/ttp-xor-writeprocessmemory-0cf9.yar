rule TTP_XOR_WriteProcessMemory_0cf9 {
  strings:
    $key_0cf9 = { 5b 8b [2] 69 a9 [2] 6f 9c [2] 41 9c [2] 7e 80 }

  condition:
    any of them
}