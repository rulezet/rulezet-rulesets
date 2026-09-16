rule TTP_XOR_WriteProcessMemory_b286 {
  strings:
    $key_b286 = { e5 f4 [2] d7 d6 [2] d1 e3 [2] ff e3 [2] c0 ff }

  condition:
    any of them
}