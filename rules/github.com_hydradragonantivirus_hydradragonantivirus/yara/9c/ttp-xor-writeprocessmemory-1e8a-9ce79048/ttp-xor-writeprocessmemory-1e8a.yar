rule TTP_XOR_WriteProcessMemory_1e8a {
  strings:
    $key_1e8a = { 49 f8 [2] 7b da [2] 7d ef [2] 53 ef [2] 6c f3 }

  condition:
    any of them
}