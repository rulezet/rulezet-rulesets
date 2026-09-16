rule TTP_XOR_WriteProcessMemory_2d37 {
  strings:
    $key_2d37 = { 7a 45 [2] 48 67 [2] 4e 52 [2] 60 52 [2] 5f 4e }

  condition:
    any of them
}