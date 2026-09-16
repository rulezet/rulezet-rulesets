rule TTP_XOR_WriteProcessMemory_a2a2 {
  strings:
    $key_a2a2 = { f5 d0 [2] c7 f2 [2] c1 c7 [2] ef c7 [2] d0 db }

  condition:
    any of them
}