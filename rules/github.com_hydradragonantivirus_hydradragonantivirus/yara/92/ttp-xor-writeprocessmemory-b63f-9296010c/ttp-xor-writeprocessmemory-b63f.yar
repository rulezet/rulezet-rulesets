rule TTP_XOR_WriteProcessMemory_b63f {
  strings:
    $key_b63f = { e1 4d [2] d3 6f [2] d5 5a [2] fb 5a [2] c4 46 }

  condition:
    any of them
}