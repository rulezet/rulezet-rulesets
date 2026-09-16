rule TTP_XOR_WriteProcessMemory_77ed {
  strings:
    $key_77ed = { 20 9f [2] 12 bd [2] 14 88 [2] 3a 88 [2] 05 94 }

  condition:
    any of them
}