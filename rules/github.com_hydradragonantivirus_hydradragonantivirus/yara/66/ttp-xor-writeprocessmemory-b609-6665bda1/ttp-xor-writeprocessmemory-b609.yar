rule TTP_XOR_WriteProcessMemory_b609 {
  strings:
    $key_b609 = { e1 7b [2] d3 59 [2] d5 6c [2] fb 6c [2] c4 70 }

  condition:
    any of them
}