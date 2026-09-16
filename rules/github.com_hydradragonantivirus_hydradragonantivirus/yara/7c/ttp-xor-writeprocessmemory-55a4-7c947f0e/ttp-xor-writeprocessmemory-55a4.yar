rule TTP_XOR_WriteProcessMemory_55a4 {
  strings:
    $key_55a4 = { 02 d6 [2] 30 f4 [2] 36 c1 [2] 18 c1 [2] 27 dd }

  condition:
    any of them
}