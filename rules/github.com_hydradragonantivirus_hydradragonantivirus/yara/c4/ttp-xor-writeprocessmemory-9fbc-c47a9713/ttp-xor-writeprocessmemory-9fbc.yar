rule TTP_XOR_WriteProcessMemory_9fbc {
  strings:
    $key_9fbc = { c8 ce [2] fa ec [2] fc d9 [2] d2 d9 [2] ed c5 }

  condition:
    any of them
}