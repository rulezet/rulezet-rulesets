rule TTP_XOR_WriteProcessMemory_0ac6 {
  strings:
    $key_0ac6 = { 5d b4 [2] 6f 96 [2] 69 a3 [2] 47 a3 [2] 78 bf }

  condition:
    any of them
}