rule TTP_XOR_WriteProcessMemory_3c8a {
  strings:
    $key_3c8a = { 6b f8 [2] 59 da [2] 5f ef [2] 71 ef [2] 4e f3 }

  condition:
    any of them
}