rule TTP_XOR_WriteProcessMemory_2577 {
  strings:
    $key_2577 = { 72 05 [2] 40 27 [2] 46 12 [2] 68 12 [2] 57 0e }

  condition:
    any of them
}