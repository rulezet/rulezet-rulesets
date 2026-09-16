rule TTP_XOR_WriteProcessMemory_b669 {
  strings:
    $key_b669 = { e1 1b [2] d3 39 [2] d5 0c [2] fb 0c [2] c4 10 }

  condition:
    any of them
}