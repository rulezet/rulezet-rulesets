rule TTP_XOR_WriteProcessMemory_1b97 {
  strings:
    $key_1b97 = { 4c e5 [2] 7e c7 [2] 78 f2 [2] 56 f2 [2] 69 ee }

  condition:
    any of them
}