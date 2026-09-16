rule TTP_XOR_WriteProcessMemory_6317 {
  strings:
    $key_6317 = { 34 65 [2] 06 47 [2] 00 72 [2] 2e 72 [2] 11 6e }

  condition:
    any of them
}