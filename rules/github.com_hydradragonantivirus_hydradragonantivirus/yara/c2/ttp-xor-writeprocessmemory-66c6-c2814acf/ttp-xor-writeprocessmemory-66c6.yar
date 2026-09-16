rule TTP_XOR_WriteProcessMemory_66c6 {
  strings:
    $key_66c6 = { 31 b4 [2] 03 96 [2] 05 a3 [2] 2b a3 [2] 14 bf }

  condition:
    any of them
}