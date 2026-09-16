rule TTP_XOR_WriteProcessMemory_2191 {
  strings:
    $key_2191 = { 76 e3 [2] 44 c1 [2] 42 f4 [2] 6c f4 [2] 53 e8 }

  condition:
    any of them
}