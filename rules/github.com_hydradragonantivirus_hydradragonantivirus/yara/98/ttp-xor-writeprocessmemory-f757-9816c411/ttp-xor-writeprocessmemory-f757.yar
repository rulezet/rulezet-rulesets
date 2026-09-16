rule TTP_XOR_WriteProcessMemory_f757 {
  strings:
    $key_f757 = { a0 25 [2] 92 07 [2] 94 32 [2] ba 32 [2] 85 2e }

  condition:
    any of them
}