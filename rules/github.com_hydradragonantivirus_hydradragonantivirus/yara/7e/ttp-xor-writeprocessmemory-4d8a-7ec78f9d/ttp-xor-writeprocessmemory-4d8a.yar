rule TTP_XOR_WriteProcessMemory_4d8a {
  strings:
    $key_4d8a = { 1a f8 [2] 28 da [2] 2e ef [2] 00 ef [2] 3f f3 }

  condition:
    any of them
}