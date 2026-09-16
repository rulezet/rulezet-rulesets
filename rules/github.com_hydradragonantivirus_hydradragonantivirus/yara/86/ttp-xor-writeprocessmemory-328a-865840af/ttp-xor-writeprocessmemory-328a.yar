rule TTP_XOR_WriteProcessMemory_328a {
  strings:
    $key_328a = { 65 f8 [2] 57 da [2] 51 ef [2] 7f ef [2] 40 f3 }

  condition:
    any of them
}