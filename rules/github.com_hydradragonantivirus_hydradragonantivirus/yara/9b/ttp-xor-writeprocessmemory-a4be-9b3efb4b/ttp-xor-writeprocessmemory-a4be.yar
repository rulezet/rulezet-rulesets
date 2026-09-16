rule TTP_XOR_WriteProcessMemory_a4be {
  strings:
    $key_a4be = { f3 cc [2] c1 ee [2] c7 db [2] e9 db [2] d6 c7 }

  condition:
    any of them
}