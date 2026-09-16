rule TTP_XOR_WriteProcessMemory_b644 {
  strings:
    $key_b644 = { e1 36 [2] d3 14 [2] d5 21 [2] fb 21 [2] c4 3d }

  condition:
    any of them
}