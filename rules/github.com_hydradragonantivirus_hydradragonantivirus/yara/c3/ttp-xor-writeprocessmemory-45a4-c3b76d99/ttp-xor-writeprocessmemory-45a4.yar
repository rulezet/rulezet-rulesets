rule TTP_XOR_WriteProcessMemory_45a4 {
  strings:
    $key_45a4 = { 12 d6 [2] 20 f4 [2] 26 c1 [2] 08 c1 [2] 37 dd }

  condition:
    any of them
}