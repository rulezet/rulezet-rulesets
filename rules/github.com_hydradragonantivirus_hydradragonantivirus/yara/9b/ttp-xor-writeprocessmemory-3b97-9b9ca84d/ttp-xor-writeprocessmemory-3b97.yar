rule TTP_XOR_WriteProcessMemory_3b97 {
  strings:
    $key_3b97 = { 6c e5 [2] 5e c7 [2] 58 f2 [2] 76 f2 [2] 49 ee }

  condition:
    any of them
}