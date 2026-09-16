rule TTP_XOR_WriteProcessMemory_1367 {
  strings:
    $key_1367 = { 44 15 [2] 76 37 [2] 70 02 [2] 5e 02 [2] 61 1e }

  condition:
    any of them
}