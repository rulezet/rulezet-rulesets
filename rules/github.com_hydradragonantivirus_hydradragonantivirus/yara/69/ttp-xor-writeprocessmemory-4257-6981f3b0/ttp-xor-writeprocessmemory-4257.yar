rule TTP_XOR_WriteProcessMemory_4257 {
  strings:
    $key_4257 = { 15 25 [2] 27 07 [2] 21 32 [2] 0f 32 [2] 30 2e }

  condition:
    any of them
}