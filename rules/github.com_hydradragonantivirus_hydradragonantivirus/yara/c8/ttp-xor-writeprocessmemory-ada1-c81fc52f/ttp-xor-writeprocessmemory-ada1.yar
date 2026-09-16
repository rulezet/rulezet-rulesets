rule TTP_XOR_WriteProcessMemory_ada1 {
  strings:
    $key_ada1 = { fa d3 [2] c8 f1 [2] ce c4 [2] e0 c4 [2] df d8 }

  condition:
    any of them
}