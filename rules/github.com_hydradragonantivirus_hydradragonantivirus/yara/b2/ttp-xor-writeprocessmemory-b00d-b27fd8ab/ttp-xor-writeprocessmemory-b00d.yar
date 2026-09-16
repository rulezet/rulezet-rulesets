rule TTP_XOR_WriteProcessMemory_b00d {
  strings:
    $key_b00d = { e7 7f [2] d5 5d [2] d3 68 [2] fd 68 [2] c2 74 }

  condition:
    any of them
}