rule TTP_XOR_WriteProcessMemory_2d70 {
  strings:
    $key_2d70 = { 7a 02 [2] 48 20 [2] 4e 15 [2] 60 15 [2] 5f 09 }

  condition:
    any of them
}