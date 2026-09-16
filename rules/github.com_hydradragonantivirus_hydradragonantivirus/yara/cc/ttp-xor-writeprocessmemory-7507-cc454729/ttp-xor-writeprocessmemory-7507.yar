rule TTP_XOR_WriteProcessMemory_7507 {
  strings:
    $key_7507 = { 22 75 [2] 10 57 [2] 16 62 [2] 38 62 [2] 07 7e }

  condition:
    any of them
}