rule TTP_XOR_WriteProcessMemory_5a8a {
  strings:
    $key_5a8a = { 0d f8 [2] 3f da [2] 39 ef [2] 17 ef [2] 28 f3 }

  condition:
    any of them
}