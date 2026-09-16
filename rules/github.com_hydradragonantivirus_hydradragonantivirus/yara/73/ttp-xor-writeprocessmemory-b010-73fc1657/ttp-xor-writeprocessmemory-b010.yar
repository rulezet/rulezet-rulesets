rule TTP_XOR_WriteProcessMemory_b010 {
  strings:
    $key_b010 = { e7 62 [2] d5 40 [2] d3 75 [2] fd 75 [2] c2 69 }

  condition:
    any of them
}