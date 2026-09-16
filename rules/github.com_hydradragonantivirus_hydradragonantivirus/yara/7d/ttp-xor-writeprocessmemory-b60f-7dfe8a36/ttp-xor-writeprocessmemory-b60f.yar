rule TTP_XOR_WriteProcessMemory_b60f {
  strings:
    $key_b60f = { e1 7d [2] d3 5f [2] d5 6a [2] fb 6a [2] c4 76 }

  condition:
    any of them
}