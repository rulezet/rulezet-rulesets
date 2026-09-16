rule TTP_XOR_WriteProcessMemory_44c1 {
  strings:
    $key_44c1 = { 13 b3 [2] 21 91 [2] 27 a4 [2] 09 a4 [2] 36 b8 }

  condition:
    any of them
}