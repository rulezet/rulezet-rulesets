rule TTP_XOR_WriteProcessMemory_b00e {
  strings:
    $key_b00e = { e7 7c [2] d5 5e [2] d3 6b [2] fd 6b [2] c2 77 }

  condition:
    any of them
}