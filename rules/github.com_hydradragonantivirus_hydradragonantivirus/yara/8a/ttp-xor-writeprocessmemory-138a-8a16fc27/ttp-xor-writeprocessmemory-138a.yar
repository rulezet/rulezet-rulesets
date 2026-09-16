rule TTP_XOR_WriteProcessMemory_138a {
  strings:
    $key_138a = { 44 f8 [2] 76 da [2] 70 ef [2] 5e ef [2] 61 f3 }

  condition:
    any of them
}