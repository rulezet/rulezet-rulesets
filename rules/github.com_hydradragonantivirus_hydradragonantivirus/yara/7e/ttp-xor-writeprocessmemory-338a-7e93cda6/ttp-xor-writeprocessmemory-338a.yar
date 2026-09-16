rule TTP_XOR_WriteProcessMemory_338a {
  strings:
    $key_338a = { 64 f8 [2] 56 da [2] 50 ef [2] 7e ef [2] 41 f3 }

  condition:
    any of them
}