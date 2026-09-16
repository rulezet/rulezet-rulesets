rule TTP_XOR_WriteProcessMemory_2d17 {
  strings:
    $key_2d17 = { 7a 65 [2] 48 47 [2] 4e 72 [2] 60 72 [2] 5f 6e }

  condition:
    any of them
}