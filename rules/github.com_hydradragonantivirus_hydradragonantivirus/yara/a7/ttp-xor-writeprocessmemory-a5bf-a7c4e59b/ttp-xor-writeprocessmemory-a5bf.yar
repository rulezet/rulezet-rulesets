rule TTP_XOR_WriteProcessMemory_a5bf {
  strings:
    $key_a5bf = { f2 cd [2] c0 ef [2] c6 da [2] e8 da [2] d7 c6 }

  condition:
    any of them
}