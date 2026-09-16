rule TTP_XOR_WriteProcessMemory_7c72 {
  strings:
    $key_7c72 = { 2b 00 [2] 19 22 [2] 1f 17 [2] 31 17 [2] 0e 0b }

  condition:
    any of them
}