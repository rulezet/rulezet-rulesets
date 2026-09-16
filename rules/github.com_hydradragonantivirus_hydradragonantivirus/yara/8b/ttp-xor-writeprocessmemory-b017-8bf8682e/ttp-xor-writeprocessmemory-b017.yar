rule TTP_XOR_WriteProcessMemory_b017 {
  strings:
    $key_b017 = { e7 65 [2] d5 47 [2] d3 72 [2] fd 72 [2] c2 6e }

  condition:
    any of them
}