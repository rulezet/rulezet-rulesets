rule TTP_XOR_WriteProcessMemory_1f8a {
  strings:
    $key_1f8a = { 48 f8 [2] 7a da [2] 7c ef [2] 52 ef [2] 6d f3 }

  condition:
    any of them
}