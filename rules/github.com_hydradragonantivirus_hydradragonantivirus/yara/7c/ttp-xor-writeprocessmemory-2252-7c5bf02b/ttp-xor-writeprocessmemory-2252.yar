rule TTP_XOR_WriteProcessMemory_2252 {
  strings:
    $key_2252 = { 75 20 [2] 47 02 [2] 41 37 [2] 6f 37 [2] 50 2b }

  condition:
    any of them
}