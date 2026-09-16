rule TTP_XOR_WriteProcessMemory_1257 {
  strings:
    $key_1257 = { 45 25 [2] 77 07 [2] 71 32 [2] 5f 32 [2] 60 2e }

  condition:
    any of them
}