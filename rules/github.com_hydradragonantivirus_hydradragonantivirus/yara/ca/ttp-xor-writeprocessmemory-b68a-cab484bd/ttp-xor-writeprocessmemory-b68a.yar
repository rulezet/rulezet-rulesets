rule TTP_XOR_WriteProcessMemory_b68a {
  strings:
    $key_b68a = { e1 f8 [2] d3 da [2] d5 ef [2] fb ef [2] c4 f3 }

  condition:
    any of them
}