rule TTP_XOR_WriteProcessMemory_0d42 {
  strings:
    $key_0d42 = { 5a 30 [2] 68 12 [2] 6e 27 [2] 40 27 [2] 7f 3b }

  condition:
    any of them
}