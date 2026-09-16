rule TTP_XOR_WriteProcessMemory_b636 {
  strings:
    $key_b636 = { e1 44 [2] d3 66 [2] d5 53 [2] fb 53 [2] c4 4f }

  condition:
    any of them
}