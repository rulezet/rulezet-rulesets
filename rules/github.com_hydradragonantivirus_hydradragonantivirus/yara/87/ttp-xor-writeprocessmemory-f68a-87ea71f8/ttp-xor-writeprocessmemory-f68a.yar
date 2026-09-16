rule TTP_XOR_WriteProcessMemory_f68a {
  strings:
    $key_f68a = { a1 f8 [2] 93 da [2] 95 ef [2] bb ef [2] 84 f3 }

  condition:
    any of them
}