rule TTP_XOR_WriteProcessMemory_61a4 {
  strings:
    $key_61a4 = { 36 d6 [2] 04 f4 [2] 02 c1 [2] 2c c1 [2] 13 dd }

  condition:
    any of them
}