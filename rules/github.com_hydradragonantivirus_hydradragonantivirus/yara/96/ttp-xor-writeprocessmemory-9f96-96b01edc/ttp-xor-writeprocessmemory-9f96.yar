rule TTP_XOR_WriteProcessMemory_9f96 {
  strings:
    $key_9f96 = { c8 e4 [2] fa c6 [2] fc f3 [2] d2 f3 [2] ed ef }

  condition:
    any of them
}