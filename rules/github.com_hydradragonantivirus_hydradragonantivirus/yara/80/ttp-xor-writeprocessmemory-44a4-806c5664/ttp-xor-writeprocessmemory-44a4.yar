rule TTP_XOR_WriteProcessMemory_44a4 {
  strings:
    $key_44a4 = { 13 d6 [2] 21 f4 [2] 27 c1 [2] 09 c1 [2] 36 dd }

  condition:
    any of them
}