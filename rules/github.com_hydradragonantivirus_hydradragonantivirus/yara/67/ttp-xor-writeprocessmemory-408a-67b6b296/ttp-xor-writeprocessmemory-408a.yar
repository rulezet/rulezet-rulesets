rule TTP_XOR_WriteProcessMemory_408a {
  strings:
    $key_408a = { 17 f8 [2] 25 da [2] 23 ef [2] 0d ef [2] 32 f3 }

  condition:
    any of them
}