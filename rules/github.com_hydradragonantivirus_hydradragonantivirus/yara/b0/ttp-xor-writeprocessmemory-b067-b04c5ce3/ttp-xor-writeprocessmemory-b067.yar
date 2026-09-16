rule TTP_XOR_WriteProcessMemory_b067 {
  strings:
    $key_b067 = { e7 15 [2] d5 37 [2] d3 02 [2] fd 02 [2] c2 1e }

  condition:
    any of them
}