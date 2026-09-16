rule TTP_XOR_WriteProcessMemory_2e8a {
  strings:
    $key_2e8a = { 79 f8 [2] 4b da [2] 4d ef [2] 63 ef [2] 5c f3 }

  condition:
    any of them
}