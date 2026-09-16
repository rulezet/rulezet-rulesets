rule TTP_XOR_WriteProcessMemory_ec8a {
  strings:
    $key_ec8a = { bb f8 [2] 89 da [2] 8f ef [2] a1 ef [2] 9e f3 }

  condition:
    any of them
}