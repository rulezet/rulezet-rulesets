rule TTP_XOR_WriteProcessMemory_2522 {
  strings:
    $key_2522 = { 72 50 [2] 40 72 [2] 46 47 [2] 68 47 [2] 57 5b }

  condition:
    any of them
}