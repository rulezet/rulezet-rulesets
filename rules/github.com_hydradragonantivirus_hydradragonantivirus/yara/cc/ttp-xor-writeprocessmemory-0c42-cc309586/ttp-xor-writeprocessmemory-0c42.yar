rule TTP_XOR_WriteProcessMemory_0c42 {
  strings:
    $key_0c42 = { 5b 30 [2] 69 12 [2] 6f 27 [2] 41 27 [2] 7e 3b }

  condition:
    any of them
}