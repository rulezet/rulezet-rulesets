rule TTP_XOR_WriteProcessMemory_4652 {
  strings:
    $key_4652 = { 11 20 [2] 23 02 [2] 25 37 [2] 0b 37 [2] 34 2b }

  condition:
    any of them
}