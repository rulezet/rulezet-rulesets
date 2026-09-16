rule TTP_XOR_WriteProcessMemory_2bd6 {
  strings:
    $key_2bd6 = { 7c a4 [2] 4e 86 [2] 48 b3 [2] 66 b3 [2] 59 af }

  condition:
    any of them
}