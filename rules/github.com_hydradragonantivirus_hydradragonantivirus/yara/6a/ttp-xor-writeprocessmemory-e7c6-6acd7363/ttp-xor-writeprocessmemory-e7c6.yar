rule TTP_XOR_WriteProcessMemory_e7c6 {
  strings:
    $key_e7c6 = { b0 b4 [2] 82 96 [2] 84 a3 [2] aa a3 [2] 95 bf }

  condition:
    any of them
}