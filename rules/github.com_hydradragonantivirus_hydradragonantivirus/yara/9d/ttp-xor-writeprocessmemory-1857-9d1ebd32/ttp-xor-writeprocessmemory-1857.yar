rule TTP_XOR_WriteProcessMemory_1857 {
  strings:
    $key_1857 = { 4f 25 [2] 7d 07 [2] 7b 32 [2] 55 32 [2] 6a 2e }

  condition:
    any of them
}