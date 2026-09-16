rule TTP_XOR_WriteProcessMemory_f58a {
  strings:
    $key_f58a = { a2 f8 [2] 90 da [2] 96 ef [2] b8 ef [2] 87 f3 }

  condition:
    any of them
}