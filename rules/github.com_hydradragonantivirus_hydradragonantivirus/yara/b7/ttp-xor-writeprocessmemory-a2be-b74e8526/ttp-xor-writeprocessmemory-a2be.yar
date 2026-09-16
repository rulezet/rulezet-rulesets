rule TTP_XOR_WriteProcessMemory_a2be {
  strings:
    $key_a2be = { f5 cc [2] c7 ee [2] c1 db [2] ef db [2] d0 c7 }

  condition:
    any of them
}