rule TTP_XOR_WriteProcessMemory_5d57 {
  strings:
    $key_5d57 = { 0a 25 [2] 38 07 [2] 3e 32 [2] 10 32 [2] 2f 2e }

  condition:
    any of them
}