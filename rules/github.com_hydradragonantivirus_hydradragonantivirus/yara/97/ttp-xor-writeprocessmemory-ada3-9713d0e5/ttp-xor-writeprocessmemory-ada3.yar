rule TTP_XOR_WriteProcessMemory_ada3 {
  strings:
    $key_ada3 = { fa d1 [2] c8 f3 [2] ce c6 [2] e0 c6 [2] df da }

  condition:
    any of them
}