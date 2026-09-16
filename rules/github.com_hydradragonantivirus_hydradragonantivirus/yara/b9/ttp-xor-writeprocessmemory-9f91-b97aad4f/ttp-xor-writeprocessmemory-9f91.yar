rule TTP_XOR_WriteProcessMemory_9f91 {
  strings:
    $key_9f91 = { c8 e3 [2] fa c1 [2] fc f4 [2] d2 f4 [2] ed e8 }

  condition:
    any of them
}