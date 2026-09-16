rule TTP_XOR_WriteProcessMemory_b035 {
  strings:
    $key_b035 = { e7 47 [2] d5 65 [2] d3 50 [2] fd 50 [2] c2 4c }

  condition:
    any of them
}