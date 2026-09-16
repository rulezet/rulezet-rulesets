rule TTP_XOR_WriteProcessMemory_3070 {
  strings:
    $key_3070 = { 67 02 [2] 55 20 [2] 53 15 [2] 7d 15 [2] 42 09 }

  condition:
    any of them
}