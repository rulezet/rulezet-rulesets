rule TTP_XOR_WriteProcessMemory_6302 {
  strings:
    $key_6302 = { 34 70 [2] 06 52 [2] 00 67 [2] 2e 67 [2] 11 7b }

  condition:
    any of them
}