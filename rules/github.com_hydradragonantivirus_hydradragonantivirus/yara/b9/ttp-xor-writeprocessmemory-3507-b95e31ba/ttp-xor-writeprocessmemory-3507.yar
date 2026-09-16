rule TTP_XOR_WriteProcessMemory_3507 {
  strings:
    $key_3507 = { 62 75 [2] 50 57 [2] 56 62 [2] 78 62 [2] 47 7e }

  condition:
    any of them
}