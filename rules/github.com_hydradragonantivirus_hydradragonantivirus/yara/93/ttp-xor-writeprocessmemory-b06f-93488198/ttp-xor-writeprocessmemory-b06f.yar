rule TTP_XOR_WriteProcessMemory_b06f {
  strings:
    $key_b06f = { e7 1d [2] d5 3f [2] d3 0a [2] fd 0a [2] c2 16 }

  condition:
    any of them
}