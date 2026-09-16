rule TTP_XOR_WriteProcessMemory_6567 {
  strings:
    $key_6567 = { 32 15 [2] 00 37 [2] 06 02 [2] 28 02 [2] 17 1e }

  condition:
    any of them
}