rule TTP_XOR_WriteProcessMemory_b05d {
  strings:
    $key_b05d = { e7 2f [2] d5 0d [2] d3 38 [2] fd 38 [2] c2 24 }

  condition:
    any of them
}