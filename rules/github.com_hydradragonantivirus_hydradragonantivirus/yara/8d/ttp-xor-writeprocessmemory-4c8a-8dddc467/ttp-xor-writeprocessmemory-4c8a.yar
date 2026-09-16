rule TTP_XOR_WriteProcessMemory_4c8a {
  strings:
    $key_4c8a = { 1b f8 [2] 29 da [2] 2f ef [2] 01 ef [2] 3e f3 }

  condition:
    any of them
}