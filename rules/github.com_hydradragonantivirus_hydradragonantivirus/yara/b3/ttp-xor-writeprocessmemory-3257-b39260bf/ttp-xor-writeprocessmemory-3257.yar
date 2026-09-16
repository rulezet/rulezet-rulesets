rule TTP_XOR_WriteProcessMemory_3257 {
  strings:
    $key_3257 = { 65 25 [2] 57 07 [2] 51 32 [2] 7f 32 [2] 40 2e }

  condition:
    any of them
}