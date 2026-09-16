rule TTP_XOR_WriteProcessMemory_03a4 {
  strings:
    $key_03a4 = { 54 d6 [2] 66 f4 [2] 60 c1 [2] 4e c1 [2] 71 dd }

  condition:
    any of them
}