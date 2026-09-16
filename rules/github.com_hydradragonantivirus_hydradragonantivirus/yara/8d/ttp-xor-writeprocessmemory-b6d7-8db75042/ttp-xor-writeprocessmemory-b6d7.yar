rule TTP_XOR_WriteProcessMemory_b6d7 {
  strings:
    $key_b6d7 = { e1 a5 [2] d3 87 [2] d5 b2 [2] fb b2 [2] c4 ae }

  condition:
    any of them
}