rule TTP_XOR_WriteProcessMemory_efc0 {
  strings:
    $key_efc0 = { b8 b2 [2] 8a 90 [2] 8c a5 [2] a2 a5 [2] 9d b9 }

  condition:
    any of them
}