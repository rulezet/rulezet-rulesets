rule TTP_XOR_WriteProcessMemory_eed0 {
  strings:
    $key_eed0 = { b9 a2 [2] 8b 80 [2] 8d b5 [2] a3 b5 [2] 9c a9 }

  condition:
    any of them
}