rule TTP_XOR_WriteProcessMemory_4d70 {
  strings:
    $key_4d70 = { 1a 02 [2] 28 20 [2] 2e 15 [2] 00 15 [2] 3f 09 }

  condition:
    any of them
}