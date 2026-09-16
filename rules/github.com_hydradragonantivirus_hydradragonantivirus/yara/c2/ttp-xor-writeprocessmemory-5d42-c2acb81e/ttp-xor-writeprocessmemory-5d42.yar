rule TTP_XOR_WriteProcessMemory_5d42 {
  strings:
    $key_5d42 = { 0a 30 [2] 38 12 [2] 3e 27 [2] 10 27 [2] 2f 3b }

  condition:
    any of them
}