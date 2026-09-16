rule TTP_XOR_WriteProcessMemory_b675 {
  strings:
    $key_b675 = { e1 07 [2] d3 25 [2] d5 10 [2] fb 10 [2] c4 0c }

  condition:
    any of them
}