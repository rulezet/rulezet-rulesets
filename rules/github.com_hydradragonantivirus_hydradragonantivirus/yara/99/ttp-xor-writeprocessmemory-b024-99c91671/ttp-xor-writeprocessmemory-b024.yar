rule TTP_XOR_WriteProcessMemory_b024 {
  strings:
    $key_b024 = { e7 56 [2] d5 74 [2] d3 41 [2] fd 41 [2] c2 5d }

  condition:
    any of them
}