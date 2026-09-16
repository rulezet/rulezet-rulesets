rule TTP_XOR_WriteProcessMemory_a0c6 {
  strings:
    $key_a0c6 = { f7 b4 [2] c5 96 [2] c3 a3 [2] ed a3 [2] d2 bf }

  condition:
    any of them
}