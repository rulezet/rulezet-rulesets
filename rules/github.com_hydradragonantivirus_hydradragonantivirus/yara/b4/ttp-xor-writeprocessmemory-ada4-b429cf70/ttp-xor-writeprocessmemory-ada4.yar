rule TTP_XOR_WriteProcessMemory_ada4 {
  strings:
    $key_ada4 = { fa d6 [2] c8 f4 [2] ce c1 [2] e0 c1 [2] df dd }

  condition:
    any of them
}