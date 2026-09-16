rule TTP_XOR_WriteProcessMemory_6577 {
  strings:
    $key_6577 = { 32 05 [2] 00 27 [2] 06 12 [2] 28 12 [2] 17 0e }

  condition:
    any of them
}