rule TTP_XOR_WriteProcessMemory_4d52 {
  strings:
    $key_4d52 = { 1a 20 [2] 28 02 [2] 2e 37 [2] 00 37 [2] 3f 2b }

  condition:
    any of them
}