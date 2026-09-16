rule TTP_XOR_WriteProcessMemory_b19d {
  strings:
    $key_b19d = { e6 ef [2] d4 cd [2] d2 f8 [2] fc f8 [2] c3 e4 }

  condition:
    any of them
}