rule TTP_XOR_WriteProcessMemory_2d07 {
  strings:
    $key_2d07 = { 7a 75 [2] 48 57 [2] 4e 62 [2] 60 62 [2] 5f 7e }

  condition:
    any of them
}