rule TTP_XOR_WriteProcessMemory_f3a4 {
  strings:
    $key_f3a4 = { a4 d6 [2] 96 f4 [2] 90 c1 [2] be c1 [2] 81 dd }

  condition:
    any of them
}