rule TTP_XOR_WriteProcessMemory_b79c {
  strings:
    $key_b79c = { e0 ee [2] d2 cc [2] d4 f9 [2] fa f9 [2] c5 e5 }

  condition:
    any of them
}