rule TTP_XOR_WriteProcessMemory_06c6 {
  strings:
    $key_06c6 = { 51 b4 [2] 63 96 [2] 65 a3 [2] 4b a3 [2] 74 bf }

  condition:
    any of them
}