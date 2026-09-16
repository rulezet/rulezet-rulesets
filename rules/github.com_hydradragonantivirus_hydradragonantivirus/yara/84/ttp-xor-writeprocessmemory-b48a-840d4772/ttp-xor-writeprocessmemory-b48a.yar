rule TTP_XOR_WriteProcessMemory_b48a {
  strings:
    $key_b48a = { e3 f8 [2] d1 da [2] d7 ef [2] f9 ef [2] c6 f3 }

  condition:
    any of them
}