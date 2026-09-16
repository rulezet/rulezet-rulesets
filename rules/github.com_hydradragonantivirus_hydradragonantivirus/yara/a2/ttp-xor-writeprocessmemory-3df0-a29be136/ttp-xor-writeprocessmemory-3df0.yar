rule TTP_XOR_WriteProcessMemory_3df0 {
  strings:
    $key_3df0 = { 6a 82 [2] 58 a0 [2] 5e 95 [2] 70 95 [2] 4f 89 }

  condition:
    any of them
}