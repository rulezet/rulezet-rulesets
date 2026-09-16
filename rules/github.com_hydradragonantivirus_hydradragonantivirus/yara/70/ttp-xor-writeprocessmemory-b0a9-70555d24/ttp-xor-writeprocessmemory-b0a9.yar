rule TTP_XOR_WriteProcessMemory_b0a9 {
  strings:
    $key_b0a9 = { e7 db [2] d5 f9 [2] d3 cc [2] fd cc [2] c2 d0 }

  condition:
    any of them
}