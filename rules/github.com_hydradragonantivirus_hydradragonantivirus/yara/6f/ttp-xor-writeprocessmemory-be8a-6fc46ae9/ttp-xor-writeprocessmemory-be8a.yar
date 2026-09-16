rule TTP_XOR_WriteProcessMemory_be8a {
  strings:
    $key_be8a = { e9 f8 [2] db da [2] dd ef [2] f3 ef [2] cc f3 }

  condition:
    any of them
}