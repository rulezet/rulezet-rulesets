rule TTP_XOR_WriteProcessMemory_b697 {
  strings:
    $key_b697 = { e1 e5 [2] d3 c7 [2] d5 f2 [2] fb f2 [2] c4 ee }

  condition:
    any of them
}