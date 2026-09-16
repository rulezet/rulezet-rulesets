rule TTP_XOR_WriteProcessMemory_b6ed {
  strings:
    $key_b6ed = { e1 9f [2] d3 bd [2] d5 88 [2] fb 88 [2] c4 94 }

  condition:
    any of them
}