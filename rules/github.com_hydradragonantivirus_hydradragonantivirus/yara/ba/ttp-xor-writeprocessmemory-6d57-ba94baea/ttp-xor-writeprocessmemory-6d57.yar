rule TTP_XOR_WriteProcessMemory_6d57 {
  strings:
    $key_6d57 = { 3a 25 [2] 08 07 [2] 0e 32 [2] 20 32 [2] 1f 2e }

  condition:
    any of them
}