rule TTP_XOR_WriteProcessMemory_98a2 {
  strings:
    $key_98a2 = { cf d0 [2] fd f2 [2] fb c7 [2] d5 c7 [2] ea db }

  condition:
    any of them
}