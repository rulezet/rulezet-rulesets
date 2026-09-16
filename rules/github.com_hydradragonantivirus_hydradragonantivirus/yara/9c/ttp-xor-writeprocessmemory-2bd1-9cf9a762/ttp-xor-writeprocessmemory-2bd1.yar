rule TTP_XOR_WriteProcessMemory_2bd1 {
  strings:
    $key_2bd1 = { 7c a3 [2] 4e 81 [2] 48 b4 [2] 66 b4 [2] 59 a8 }

  condition:
    any of them
}