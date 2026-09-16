rule TTP_XOR_WriteProcessMemory_3097 {
  strings:
    $key_3097 = { 67 e5 [2] 55 c7 [2] 53 f2 [2] 7d f2 [2] 42 ee }

  condition:
    any of them
}