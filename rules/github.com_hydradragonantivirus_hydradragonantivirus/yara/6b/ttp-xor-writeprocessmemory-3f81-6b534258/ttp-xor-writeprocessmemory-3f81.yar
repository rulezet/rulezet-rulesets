rule TTP_XOR_WriteProcessMemory_3f81 {
  strings:
    $key_3f81 = { 68 f3 [2] 5a d1 [2] 5c e4 [2] 72 e4 [2] 4d f8 }

  condition:
    any of them
}