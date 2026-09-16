rule TTP_XOR_WriteProcessMemory_2d22 {
  strings:
    $key_2d22 = { 7a 50 [2] 48 72 [2] 4e 47 [2] 60 47 [2] 5f 5b }

  condition:
    any of them
}