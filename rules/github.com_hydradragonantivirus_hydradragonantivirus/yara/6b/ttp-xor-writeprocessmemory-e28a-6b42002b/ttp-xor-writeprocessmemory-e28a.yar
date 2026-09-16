rule TTP_XOR_WriteProcessMemory_e28a {
  strings:
    $key_e28a = { b5 f8 [2] 87 da [2] 81 ef [2] af ef [2] 90 f3 }

  condition:
    any of them
}