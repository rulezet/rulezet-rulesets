rule TTP_XOR_WriteProcessMemory_b05e {
  strings:
    $key_b05e = { e7 2c [2] d5 0e [2] d3 3b [2] fd 3b [2] c2 27 }

  condition:
    any of them
}