rule TTP_XOR_WriteProcessMemory_3757 {
  strings:
    $key_3757 = { 60 25 [2] 52 07 [2] 54 32 [2] 7a 32 [2] 45 2e }

  condition:
    any of them
}