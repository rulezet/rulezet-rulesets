rule TTP_XOR_WriteProcessMemory_b60e {
  strings:
    $key_b60e = { e1 7c [2] d3 5e [2] d5 6b [2] fb 6b [2] c4 77 }

  condition:
    any of them
}