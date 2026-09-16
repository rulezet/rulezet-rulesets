rule TTP_XOR_WriteProcessMemory_b1bf {
  strings:
    $key_b1bf = { e6 cd [2] d4 ef [2] d2 da [2] fc da [2] c3 c6 }

  condition:
    any of them
}