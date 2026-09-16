rule TTP_XOR_WriteProcessMemory_248a {
  strings:
    $key_248a = { 73 f8 [2] 41 da [2] 47 ef [2] 69 ef [2] 56 f3 }

  condition:
    any of them
}