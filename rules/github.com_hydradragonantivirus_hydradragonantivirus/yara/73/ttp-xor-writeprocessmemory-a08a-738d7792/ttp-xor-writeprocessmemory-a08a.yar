rule TTP_XOR_WriteProcessMemory_a08a {
  strings:
    $key_a08a = { f7 f8 [2] c5 da [2] c3 ef [2] ed ef [2] d2 f3 }

  condition:
    any of them
}