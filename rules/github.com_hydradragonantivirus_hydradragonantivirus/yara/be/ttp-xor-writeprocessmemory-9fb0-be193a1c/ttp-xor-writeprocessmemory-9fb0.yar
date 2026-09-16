rule TTP_XOR_WriteProcessMemory_9fb0 {
  strings:
    $key_9fb0 = { c8 c2 [2] fa e0 [2] fc d5 [2] d2 d5 [2] ed c9 }

  condition:
    any of them
}