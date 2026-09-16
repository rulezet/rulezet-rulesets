rule TTP_XOR_WriteProcessMemory_a18a {
  strings:
    $key_a18a = { f6 f8 [2] c4 da [2] c2 ef [2] ec ef [2] d3 f3 }

  condition:
    any of them
}