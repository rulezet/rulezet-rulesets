rule TTP_XOR_WriteProcessMemory_b03e {
  strings:
    $key_b03e = { e7 4c [2] d5 6e [2] d3 5b [2] fd 5b [2] c2 47 }

  condition:
    any of them
}