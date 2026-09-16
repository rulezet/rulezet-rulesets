rule TTP_XOR_WriteProcessMemory_b665 {
  strings:
    $key_b665 = { e1 17 [2] d3 35 [2] d5 00 [2] fb 00 [2] c4 1c }

  condition:
    any of them
}