rule TTP_XOR_WriteProcessMemory_f38a {
  strings:
    $key_f38a = { a4 f8 [2] 96 da [2] 90 ef [2] be ef [2] 81 f3 }

  condition:
    any of them
}