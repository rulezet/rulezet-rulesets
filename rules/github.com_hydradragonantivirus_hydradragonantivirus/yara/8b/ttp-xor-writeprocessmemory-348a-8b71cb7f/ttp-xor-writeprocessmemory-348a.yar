rule TTP_XOR_WriteProcessMemory_348a {
  strings:
    $key_348a = { 63 f8 [2] 51 da [2] 57 ef [2] 79 ef [2] 46 f3 }

  condition:
    any of them
}