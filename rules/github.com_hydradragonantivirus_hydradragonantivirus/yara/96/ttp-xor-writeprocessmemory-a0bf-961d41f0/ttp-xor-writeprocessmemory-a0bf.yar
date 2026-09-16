rule TTP_XOR_WriteProcessMemory_a0bf {
  strings:
    $key_a0bf = { f7 cd [2] c5 ef [2] c3 da [2] ed da [2] d2 c6 }

  condition:
    any of them
}