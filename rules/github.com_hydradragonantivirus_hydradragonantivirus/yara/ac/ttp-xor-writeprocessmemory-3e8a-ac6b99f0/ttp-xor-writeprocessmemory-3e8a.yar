rule TTP_XOR_WriteProcessMemory_3e8a {
  strings:
    $key_3e8a = { 69 f8 [2] 5b da [2] 5d ef [2] 73 ef [2] 4c f3 }

  condition:
    any of them
}