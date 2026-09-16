rule TTP_XOR_WriteProcessMemory_1d17 {
  strings:
    $key_1d17 = { 4a 65 [2] 78 47 [2] 7e 72 [2] 50 72 [2] 6f 6e }

  condition:
    any of them
}