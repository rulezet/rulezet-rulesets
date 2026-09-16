rule TTP_XOR_WriteProcessMemory_2862 {
  strings:
    $key_2862 = { 7f 10 [2] 4d 32 [2] 4b 07 [2] 65 07 [2] 5a 1b }

  condition:
    any of them
}