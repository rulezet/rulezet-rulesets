rule TTP_XOR_WriteProcessMemory_bb8a {
  strings:
    $key_bb8a = { ec f8 [2] de da [2] d8 ef [2] f6 ef [2] c9 f3 }

  condition:
    any of them
}