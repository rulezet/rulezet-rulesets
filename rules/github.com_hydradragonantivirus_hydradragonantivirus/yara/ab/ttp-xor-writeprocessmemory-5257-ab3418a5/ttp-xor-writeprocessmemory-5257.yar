rule TTP_XOR_WriteProcessMemory_5257 {
  strings:
    $key_5257 = { 05 25 [2] 37 07 [2] 31 32 [2] 1f 32 [2] 20 2e }

  condition:
    any of them
}