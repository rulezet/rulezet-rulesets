rule TTP_XOR_WriteProcessMemory_ab8a {
  strings:
    $key_ab8a = { fc f8 [2] ce da [2] c8 ef [2] e6 ef [2] d9 f3 }

  condition:
    any of them
}