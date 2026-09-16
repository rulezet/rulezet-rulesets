rule TTP_XOR_WriteProcessMemory_2b97 {
  strings:
    $key_2b97 = { 7c e5 [2] 4e c7 [2] 48 f2 [2] 66 f2 [2] 59 ee }

  condition:
    any of them
}