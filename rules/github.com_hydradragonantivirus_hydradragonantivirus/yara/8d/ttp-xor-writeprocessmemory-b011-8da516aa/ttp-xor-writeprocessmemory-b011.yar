rule TTP_XOR_WriteProcessMemory_b011 {
  strings:
    $key_b011 = { e7 63 [2] d5 41 [2] d3 74 [2] fd 74 [2] c2 68 }

  condition:
    any of them
}