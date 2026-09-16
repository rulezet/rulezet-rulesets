rule TTP_XOR_WriteProcessMemory_6d8a {
  strings:
    $key_6d8a = { 3a f8 [2] 08 da [2] 0e ef [2] 20 ef [2] 1f f3 }

  condition:
    any of them
}