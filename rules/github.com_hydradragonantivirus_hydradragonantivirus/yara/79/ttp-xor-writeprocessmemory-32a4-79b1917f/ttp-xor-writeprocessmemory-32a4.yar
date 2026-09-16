rule TTP_XOR_WriteProcessMemory_32a4 {
  strings:
    $key_32a4 = { 65 d6 [2] 57 f4 [2] 51 c1 [2] 7f c1 [2] 40 dd }

  condition:
    any of them
}