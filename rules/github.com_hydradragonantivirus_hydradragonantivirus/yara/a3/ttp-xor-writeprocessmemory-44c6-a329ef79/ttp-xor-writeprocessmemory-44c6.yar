rule TTP_XOR_WriteProcessMemory_44c6 {
  strings:
    $key_44c6 = { 13 b4 [2] 21 96 [2] 27 a3 [2] 09 a3 [2] 36 bf }

  condition:
    any of them
}