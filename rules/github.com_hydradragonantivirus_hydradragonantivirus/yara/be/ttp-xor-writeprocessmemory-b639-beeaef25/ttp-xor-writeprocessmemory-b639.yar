rule TTP_XOR_WriteProcessMemory_b639 {
  strings:
    $key_b639 = { e1 4b [2] d3 69 [2] d5 5c [2] fb 5c [2] c4 40 }

  condition:
    any of them
}