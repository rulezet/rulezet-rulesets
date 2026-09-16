rule TTP_XOR_WriteProcessMemory_fc8a {
  strings:
    $key_fc8a = { ab f8 [2] 99 da [2] 9f ef [2] b1 ef [2] 8e f3 }

  condition:
    any of them
}