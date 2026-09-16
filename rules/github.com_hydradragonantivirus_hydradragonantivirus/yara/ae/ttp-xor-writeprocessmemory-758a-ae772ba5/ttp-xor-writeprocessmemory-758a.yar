rule TTP_XOR_WriteProcessMemory_758a {
  strings:
    $key_758a = { 22 f8 [2] 10 da [2] 16 ef [2] 38 ef [2] 07 f3 }

  condition:
    any of them
}