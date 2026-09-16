rule TTP_XOR_WriteProcessMemory_3191 {
  strings:
    $key_3191 = { 66 e3 [2] 54 c1 [2] 52 f4 [2] 7c f4 [2] 43 e8 }

  condition:
    any of them
}