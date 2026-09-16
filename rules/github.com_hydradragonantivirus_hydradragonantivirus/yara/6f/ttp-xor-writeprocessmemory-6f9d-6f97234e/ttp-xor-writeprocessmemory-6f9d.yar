rule TTP_XOR_WriteProcessMemory_6f9d {
  strings:
    $key_6f9d = { 38 ef [2] 0a cd [2] 0c f8 [2] 22 f8 [2] 1d e4 }

  condition:
    any of them
}