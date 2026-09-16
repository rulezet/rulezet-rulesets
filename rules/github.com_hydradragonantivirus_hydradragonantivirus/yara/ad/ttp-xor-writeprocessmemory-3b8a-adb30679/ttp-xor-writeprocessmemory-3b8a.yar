rule TTP_XOR_WriteProcessMemory_3b8a {
  strings:
    $key_3b8a = { 6c f8 [2] 5e da [2] 58 ef [2] 76 ef [2] 49 f3 }

  condition:
    any of them
}