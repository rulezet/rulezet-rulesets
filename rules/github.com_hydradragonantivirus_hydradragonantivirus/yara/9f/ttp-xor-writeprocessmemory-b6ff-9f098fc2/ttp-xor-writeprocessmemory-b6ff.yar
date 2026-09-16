rule TTP_XOR_WriteProcessMemory_b6ff {
  strings:
    $key_b6ff = { e1 8d [2] d3 af [2] d5 9a [2] fb 9a [2] c4 86 }

  condition:
    any of them
}