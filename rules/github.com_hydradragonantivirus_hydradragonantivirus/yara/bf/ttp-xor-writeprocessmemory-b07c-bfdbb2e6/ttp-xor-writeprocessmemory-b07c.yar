rule TTP_XOR_WriteProcessMemory_b07c {
  strings:
    $key_b07c = { e7 0e [2] d5 2c [2] d3 19 [2] fd 19 [2] c2 05 }

  condition:
    any of them
}