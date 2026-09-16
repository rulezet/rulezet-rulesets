rule TTP_XOR_WriteProcessMemory_b1be {
  strings:
    $key_b1be = { e6 cc [2] d4 ee [2] d2 db [2] fc db [2] c3 c7 }

  condition:
    any of them
}