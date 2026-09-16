rule TTP_XOR_WriteProcessMemory_98a5 {
  strings:
    $key_98a5 = { cf d7 [2] fd f5 [2] fb c0 [2] d5 c0 [2] ea dc }

  condition:
    any of them
}