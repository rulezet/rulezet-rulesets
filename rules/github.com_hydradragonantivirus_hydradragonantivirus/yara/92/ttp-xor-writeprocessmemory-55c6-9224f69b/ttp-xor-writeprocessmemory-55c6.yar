rule TTP_XOR_WriteProcessMemory_55c6 {
  strings:
    $key_55c6 = { 02 b4 [2] 30 96 [2] 36 a3 [2] 18 a3 [2] 27 bf }

  condition:
    any of them
}