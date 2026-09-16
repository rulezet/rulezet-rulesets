rule TTP_XOR_WriteProcessMemory_1c8a {
  strings:
    $key_1c8a = { 4b f8 [2] 79 da [2] 7f ef [2] 51 ef [2] 6e f3 }

  condition:
    any of them
}