rule TTP_XOR_WriteProcessMemory_6b8a {
  strings:
    $key_6b8a = { 3c f8 [2] 0e da [2] 08 ef [2] 26 ef [2] 19 f3 }

  condition:
    any of them
}