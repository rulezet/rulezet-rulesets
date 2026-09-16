rule TTP_XOR_WriteProcessMemory_44d6 {
  strings:
    $key_44d6 = { 13 a4 [2] 21 86 [2] 27 b3 [2] 09 b3 [2] 36 af }

  condition:
    any of them
}