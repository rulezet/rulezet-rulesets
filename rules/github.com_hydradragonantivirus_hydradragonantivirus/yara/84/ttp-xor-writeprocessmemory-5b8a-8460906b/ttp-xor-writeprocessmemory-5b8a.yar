rule TTP_XOR_WriteProcessMemory_5b8a {
  strings:
    $key_5b8a = { 0c f8 [2] 3e da [2] 38 ef [2] 16 ef [2] 29 f3 }

  condition:
    any of them
}