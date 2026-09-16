rule TTP_XOR_WriteProcessMemory_708a {
  strings:
    $key_708a = { 27 f8 [2] 15 da [2] 13 ef [2] 3d ef [2] 02 f3 }

  condition:
    any of them
}