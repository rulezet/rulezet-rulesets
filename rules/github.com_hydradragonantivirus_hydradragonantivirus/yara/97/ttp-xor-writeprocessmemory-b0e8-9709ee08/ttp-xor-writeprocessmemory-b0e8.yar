rule TTP_XOR_WriteProcessMemory_b0e8 {
  strings:
    $key_b0e8 = { e7 9a [2] d5 b8 [2] d3 8d [2] fd 8d [2] c2 91 }

  condition:
    any of them
}