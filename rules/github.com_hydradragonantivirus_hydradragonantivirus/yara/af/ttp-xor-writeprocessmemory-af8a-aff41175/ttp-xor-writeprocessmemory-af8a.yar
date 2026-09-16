rule TTP_XOR_WriteProcessMemory_af8a {
  strings:
    $key_af8a = { f8 f8 [2] ca da [2] cc ef [2] e2 ef [2] dd f3 }

  condition:
    any of them
}