rule TTP_XOR_WriteProcessMemory_b0ff {
  strings:
    $key_b0ff = { e7 8d [2] d5 af [2] d3 9a [2] fd 9a [2] c2 86 }

  condition:
    any of them
}