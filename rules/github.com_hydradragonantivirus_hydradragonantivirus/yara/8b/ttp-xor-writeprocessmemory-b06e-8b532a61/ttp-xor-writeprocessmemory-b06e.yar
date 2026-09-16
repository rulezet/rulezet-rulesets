rule TTP_XOR_WriteProcessMemory_b06e {
  strings:
    $key_b06e = { e7 1c [2] d5 3e [2] d3 0b [2] fd 0b [2] c2 17 }

  condition:
    any of them
}