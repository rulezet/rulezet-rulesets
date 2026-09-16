rule TTP_XOR_WriteProcessMemory_b6f4 {
  strings:
    $key_b6f4 = { e1 86 [2] d3 a4 [2] d5 91 [2] fb 91 [2] c4 8d }

  condition:
    any of them
}