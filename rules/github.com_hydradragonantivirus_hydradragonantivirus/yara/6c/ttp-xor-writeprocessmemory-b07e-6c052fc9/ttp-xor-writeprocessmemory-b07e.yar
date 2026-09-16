rule TTP_XOR_WriteProcessMemory_b07e {
  strings:
    $key_b07e = { e7 0c [2] d5 2e [2] d3 1b [2] fd 1b [2] c2 07 }

  condition:
    any of them
}