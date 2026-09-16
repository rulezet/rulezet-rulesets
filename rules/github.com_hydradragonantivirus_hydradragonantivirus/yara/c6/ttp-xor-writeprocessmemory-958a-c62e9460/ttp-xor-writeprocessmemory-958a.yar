rule TTP_XOR_WriteProcessMemory_958a {
  strings:
    $key_958a = { c2 f8 [2] f0 da [2] f6 ef [2] d8 ef [2] e7 f3 }

  condition:
    any of them
}