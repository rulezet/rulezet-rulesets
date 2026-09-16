rule TTP_XOR_WriteProcessMemory_0877 {
  strings:
    $key_0877 = { 5f 05 [2] 6d 27 [2] 6b 12 [2] 45 12 [2] 7a 0e }

  condition:
    any of them
}