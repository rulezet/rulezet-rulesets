rule TTP_XOR_WriteProcessMemory_528a {
  strings:
    $key_528a = { 05 f8 [2] 37 da [2] 31 ef [2] 1f ef [2] 20 f3 }

  condition:
    any of them
}