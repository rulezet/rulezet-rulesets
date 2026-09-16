rule TTP_XOR_WriteProcessMemory_eed1 {
  strings:
    $key_eed1 = { b9 a3 [2] 8b 81 [2] 8d b4 [2] a3 b4 [2] 9c a8 }

  condition:
    any of them
}