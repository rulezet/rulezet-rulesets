rule TTP_XOR_WriteProcessMemory_5d72 {
  strings:
    $key_5d72 = { 0a 00 [2] 38 22 [2] 3e 17 [2] 10 17 [2] 2f 0b }

  condition:
    any of them
}