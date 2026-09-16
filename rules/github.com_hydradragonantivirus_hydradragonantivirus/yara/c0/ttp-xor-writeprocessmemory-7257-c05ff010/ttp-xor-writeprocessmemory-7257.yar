rule TTP_XOR_WriteProcessMemory_7257 {
  strings:
    $key_7257 = { 25 25 [2] 17 07 [2] 11 32 [2] 3f 32 [2] 00 2e }

  condition:
    any of them
}