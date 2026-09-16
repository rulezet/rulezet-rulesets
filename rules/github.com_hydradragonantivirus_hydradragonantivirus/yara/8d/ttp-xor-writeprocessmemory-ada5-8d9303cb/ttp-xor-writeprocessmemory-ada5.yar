rule TTP_XOR_WriteProcessMemory_ada5 {
  strings:
    $key_ada5 = { fa d7 [2] c8 f5 [2] ce c0 [2] e0 c0 [2] df dc }

  condition:
    any of them
}