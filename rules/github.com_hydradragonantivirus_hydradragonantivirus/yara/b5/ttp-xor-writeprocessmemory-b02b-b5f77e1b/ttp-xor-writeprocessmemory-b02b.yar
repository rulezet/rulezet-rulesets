rule TTP_XOR_WriteProcessMemory_b02b {
  strings:
    $key_b02b = { e7 59 [2] d5 7b [2] d3 4e [2] fd 4e [2] c2 52 }

  condition:
    any of them
}