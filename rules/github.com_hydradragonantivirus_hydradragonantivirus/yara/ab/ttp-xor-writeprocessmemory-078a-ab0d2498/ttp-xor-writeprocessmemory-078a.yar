rule TTP_XOR_WriteProcessMemory_078a {
  strings:
    $key_078a = { 50 f8 [2] 62 da [2] 64 ef [2] 4a ef [2] 75 f3 }

  condition:
    any of them
}