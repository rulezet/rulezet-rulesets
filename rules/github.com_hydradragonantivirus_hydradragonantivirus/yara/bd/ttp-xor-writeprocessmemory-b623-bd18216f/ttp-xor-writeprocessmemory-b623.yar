rule TTP_XOR_WriteProcessMemory_b623 {
  strings:
    $key_b623 = { e1 51 [2] d3 73 [2] d5 46 [2] fb 46 [2] c4 5a }

  condition:
    any of them
}