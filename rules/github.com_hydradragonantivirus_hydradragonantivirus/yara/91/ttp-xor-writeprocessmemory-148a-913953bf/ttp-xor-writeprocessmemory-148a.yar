rule TTP_XOR_WriteProcessMemory_148a {
  strings:
    $key_148a = { 43 f8 [2] 71 da [2] 77 ef [2] 59 ef [2] 66 f3 }

  condition:
    any of them
}