rule TTP_XOR_WriteProcessMemory_3762 {
  strings:
    $key_3762 = { 60 10 [2] 52 32 [2] 54 07 [2] 7a 07 [2] 45 1b }

  condition:
    any of them
}