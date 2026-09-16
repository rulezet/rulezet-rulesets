rule TTP_XOR_WriteProcessMemory_2d43 {
  strings:
    $key_2d43 = { 7a 31 [2] 48 13 [2] 4e 26 [2] 60 26 [2] 5f 3a }

  condition:
    any of them
}