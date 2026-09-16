rule TTP_XOR_WriteProcessMemory_2d52 {
  strings:
    $key_2d52 = { 7a 20 [2] 48 02 [2] 4e 37 [2] 60 37 [2] 5f 2b }

  condition:
    any of them
}