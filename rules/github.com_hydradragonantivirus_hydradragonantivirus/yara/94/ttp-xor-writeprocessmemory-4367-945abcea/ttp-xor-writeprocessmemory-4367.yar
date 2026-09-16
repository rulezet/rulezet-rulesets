rule TTP_XOR_WriteProcessMemory_4367 {
  strings:
    $key_4367 = { 14 15 [2] 26 37 [2] 20 02 [2] 0e 02 [2] 31 1e }

  condition:
    any of them
}