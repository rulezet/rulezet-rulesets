rule TTP_XOR_WriteProcessMemory_428a {
  strings:
    $key_428a = { 15 f8 [2] 27 da [2] 21 ef [2] 0f ef [2] 30 f3 }

  condition:
    any of them
}