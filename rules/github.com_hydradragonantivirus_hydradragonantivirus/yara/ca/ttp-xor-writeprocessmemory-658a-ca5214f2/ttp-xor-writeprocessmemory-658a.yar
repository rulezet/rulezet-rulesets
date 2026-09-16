rule TTP_XOR_WriteProcessMemory_658a {
  strings:
    $key_658a = { 32 f8 [2] 00 da [2] 06 ef [2] 28 ef [2] 17 f3 }

  condition:
    any of them
}