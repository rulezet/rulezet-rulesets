rule TTP_XOR_WriteProcessMemory_b628 {
  strings:
    $key_b628 = { e1 5a [2] d3 78 [2] d5 4d [2] fb 4d [2] c4 51 }

  condition:
    any of them
}