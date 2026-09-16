rule TTP_XOR_WriteProcessMemory_4e8a {
  strings:
    $key_4e8a = { 19 f8 [2] 2b da [2] 2d ef [2] 03 ef [2] 3c f3 }

  condition:
    any of them
}