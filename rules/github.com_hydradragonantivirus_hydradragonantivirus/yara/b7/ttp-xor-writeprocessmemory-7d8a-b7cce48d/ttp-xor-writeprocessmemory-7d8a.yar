rule TTP_XOR_WriteProcessMemory_7d8a {
  strings:
    $key_7d8a = { 2a f8 [2] 18 da [2] 1e ef [2] 30 ef [2] 0f f3 }

  condition:
    any of them
}