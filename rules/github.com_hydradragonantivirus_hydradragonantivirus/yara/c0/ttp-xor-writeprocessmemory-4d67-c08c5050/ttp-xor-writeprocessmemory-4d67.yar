rule TTP_XOR_WriteProcessMemory_4d67 {
  strings:
    $key_4d67 = { 1a 15 [2] 28 37 [2] 2e 02 [2] 00 02 [2] 3f 1e }

  condition:
    any of them
}