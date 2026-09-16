rule TTP_XOR_WriteProcessMemory_b07b {
  strings:
    $key_b07b = { e7 09 [2] d5 2b [2] d3 1e [2] fd 1e [2] c2 02 }

  condition:
    any of them
}