rule TTP_XOR_WriteProcessMemory_f69d {
  strings:
    $key_f69d = { a1 ef [2] 93 cd [2] 95 f8 [2] bb f8 [2] 84 e4 }

  condition:
    any of them
}