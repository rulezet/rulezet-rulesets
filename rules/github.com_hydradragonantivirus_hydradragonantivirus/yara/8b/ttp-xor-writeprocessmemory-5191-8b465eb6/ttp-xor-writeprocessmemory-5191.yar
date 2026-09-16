rule TTP_XOR_WriteProcessMemory_5191 {
  strings:
    $key_5191 = { 06 e3 [2] 34 c1 [2] 32 f4 [2] 1c f4 [2] 23 e8 }

  condition:
    any of them
}