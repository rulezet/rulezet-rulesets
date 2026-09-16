rule TTP_XOR_WriteProcessMemory_b061 {
  strings:
    $key_b061 = { e7 13 [2] d5 31 [2] d3 04 [2] fd 04 [2] c2 18 }

  condition:
    any of them
}