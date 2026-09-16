rule TTP_XOR_WriteProcessMemory_e0c6 {
  strings:
    $key_e0c6 = { b7 b4 [2] 85 96 [2] 83 a3 [2] ad a3 [2] 92 bf }

  condition:
    any of them
}