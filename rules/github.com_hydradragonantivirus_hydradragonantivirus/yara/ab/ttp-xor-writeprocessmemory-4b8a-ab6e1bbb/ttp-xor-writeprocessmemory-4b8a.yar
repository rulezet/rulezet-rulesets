rule TTP_XOR_WriteProcessMemory_4b8a {
  strings:
    $key_4b8a = { 1c f8 [2] 2e da [2] 28 ef [2] 06 ef [2] 39 f3 }

  condition:
    any of them
}