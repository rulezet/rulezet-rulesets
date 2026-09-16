rule TTP_XOR_WriteProcessMemory_2d67 {
  strings:
    $key_2d67 = { 7a 15 [2] 48 37 [2] 4e 02 [2] 60 02 [2] 5f 1e }

  condition:
    any of them
}