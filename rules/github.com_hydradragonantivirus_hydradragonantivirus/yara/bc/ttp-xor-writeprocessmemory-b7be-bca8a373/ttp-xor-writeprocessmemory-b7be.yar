rule TTP_XOR_WriteProcessMemory_b7be {
  strings:
    $key_b7be = { e0 cc [2] d2 ee [2] d4 db [2] fa db [2] c5 c7 }

  condition:
    any of them
}