rule TTP_XOR_WriteProcessMemory_a2a4 {
  strings:
    $key_a2a4 = { f5 d6 [2] c7 f4 [2] c1 c1 [2] ef c1 [2] d0 dd }

  condition:
    any of them
}