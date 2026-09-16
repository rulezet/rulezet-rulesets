rule TTP_XOR_WriteProcessMemory_ada9 {
  strings:
    $key_ada9 = { fa db [2] c8 f9 [2] ce cc [2] e0 cc [2] df d0 }

  condition:
    any of them
}