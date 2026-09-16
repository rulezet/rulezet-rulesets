rule TTP_XOR_WriteProcessMemory_b616 {
  strings:
    $key_b616 = { e1 64 [2] d3 46 [2] d5 73 [2] fb 73 [2] c4 6f }

  condition:
    any of them
}