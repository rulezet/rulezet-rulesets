rule TTP_XOR_WriteProcessMemory_008a {
  strings:
    $key_008a = { 57 f8 [2] 65 da [2] 63 ef [2] 4d ef [2] 72 f3 }

  condition:
    any of them
}