rule TTP_XOR_WriteProcessMemory_5f9d {
  strings:
    $key_5f9d = { 08 ef [2] 3a cd [2] 3c f8 [2] 12 f8 [2] 2d e4 }

  condition:
    any of them
}