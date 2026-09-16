rule TTP_XOR_WriteProcessMemory_b67f {
  strings:
    $key_b67f = { e1 0d [2] d3 2f [2] d5 1a [2] fb 1a [2] c4 06 }

  condition:
    any of them
}