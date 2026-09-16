rule TTP_XOR_WriteProcessMemory_b09d {
  strings:
    $key_b09d = { e7 ef [2] d5 cd [2] d3 f8 [2] fd f8 [2] c2 e4 }

  condition:
    any of them
}