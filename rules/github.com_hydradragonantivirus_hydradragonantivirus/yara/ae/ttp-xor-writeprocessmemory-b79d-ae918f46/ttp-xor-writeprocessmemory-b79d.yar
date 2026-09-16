rule TTP_XOR_WriteProcessMemory_b79d {
  strings:
    $key_b79d = { e0 ef [2] d2 cd [2] d4 f8 [2] fa f8 [2] c5 e4 }

  condition:
    any of them
}