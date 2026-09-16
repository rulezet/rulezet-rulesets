rule TTP_XOR_WriteProcessMemory_2d57 {
  strings:
    $key_2d57 = { 7a 25 [2] 48 07 [2] 4e 32 [2] 60 32 [2] 5f 2e }

  condition:
    any of them
}