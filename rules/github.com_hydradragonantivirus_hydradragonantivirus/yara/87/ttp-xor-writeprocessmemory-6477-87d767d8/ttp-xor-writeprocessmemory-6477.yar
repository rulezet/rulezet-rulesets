rule TTP_XOR_WriteProcessMemory_6477 {
  strings:
    $key_6477 = { 33 05 [2] 01 27 [2] 07 12 [2] 29 12 [2] 16 0e }

  condition:
    any of them
}