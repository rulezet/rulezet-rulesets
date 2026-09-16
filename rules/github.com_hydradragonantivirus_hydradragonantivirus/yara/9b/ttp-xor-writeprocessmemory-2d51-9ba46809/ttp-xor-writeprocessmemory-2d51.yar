rule TTP_XOR_WriteProcessMemory_2d51 {
  strings:
    $key_2d51 = { 7a 23 [2] 48 01 [2] 4e 34 [2] 60 34 [2] 5f 28 }

  condition:
    any of them
}