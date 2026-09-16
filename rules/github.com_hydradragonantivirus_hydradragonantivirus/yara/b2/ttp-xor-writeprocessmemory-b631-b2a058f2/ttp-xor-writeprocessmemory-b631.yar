rule TTP_XOR_WriteProcessMemory_b631 {
  strings:
    $key_b631 = { e1 43 [2] d3 61 [2] d5 54 [2] fb 54 [2] c4 48 }

  condition:
    any of them
}