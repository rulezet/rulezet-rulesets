rule TTP_XOR_WriteProcessMemory_b02e {
  strings:
    $key_b02e = { e7 5c [2] d5 7e [2] d3 4b [2] fd 4b [2] c2 57 }

  condition:
    any of them
}