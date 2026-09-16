rule TTP_XOR_WriteProcessMemory_b6e5 {
  strings:
    $key_b6e5 = { e1 97 [2] d3 b5 [2] d5 80 [2] fb 80 [2] c4 9c }

  condition:
    any of them
}