rule TTP_XOR_WriteProcessMemory_b676 {
  strings:
    $key_b676 = { e1 04 [2] d3 26 [2] d5 13 [2] fb 13 [2] c4 0f }

  condition:
    any of them
}