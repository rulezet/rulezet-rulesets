rule TTP_XOR_WriteProcessMemory_858a {
  strings:
    $key_858a = { d2 f8 [2] e0 da [2] e6 ef [2] c8 ef [2] f7 f3 }

  condition:
    any of them
}