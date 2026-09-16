rule TTP_XOR_WriteProcessMemory_5f8a {
  strings:
    $key_5f8a = { 08 f8 [2] 3a da [2] 3c ef [2] 12 ef [2] 2d f3 }

  condition:
    any of them
}