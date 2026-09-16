rule TTP_XOR_WriteProcessMemory_b6ee {
  strings:
    $key_b6ee = { e1 9c [2] d3 be [2] d5 8b [2] fb 8b [2] c4 97 }

  condition:
    any of them
}