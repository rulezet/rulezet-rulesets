rule TTP_XOR_WriteProcessMemory_7267 {
  strings:
    $key_7267 = { 25 15 [2] 17 37 [2] 11 02 [2] 3f 02 [2] 00 1e }

  condition:
    any of them
}