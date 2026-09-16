rule TTP_XOR_WriteProcessMemory_b69d {
  strings:
    $key_b69d = { e1 ef [2] d3 cd [2] d5 f8 [2] fb f8 [2] c4 e4 }

  condition:
    any of them
}