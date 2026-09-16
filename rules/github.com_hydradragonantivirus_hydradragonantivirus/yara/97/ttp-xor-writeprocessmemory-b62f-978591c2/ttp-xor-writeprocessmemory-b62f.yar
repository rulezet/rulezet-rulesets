rule TTP_XOR_WriteProcessMemory_b62f {
  strings:
    $key_b62f = { e1 5d [2] d3 7f [2] d5 4a [2] fb 4a [2] c4 56 }

  condition:
    any of them
}