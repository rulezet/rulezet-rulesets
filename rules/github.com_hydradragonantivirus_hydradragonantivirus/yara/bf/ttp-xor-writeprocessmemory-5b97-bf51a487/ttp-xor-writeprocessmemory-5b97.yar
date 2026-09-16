rule TTP_XOR_WriteProcessMemory_5b97 {
  strings:
    $key_5b97 = { 0c e5 [2] 3e c7 [2] 38 f2 [2] 16 f2 [2] 29 ee }

  condition:
    any of them
}