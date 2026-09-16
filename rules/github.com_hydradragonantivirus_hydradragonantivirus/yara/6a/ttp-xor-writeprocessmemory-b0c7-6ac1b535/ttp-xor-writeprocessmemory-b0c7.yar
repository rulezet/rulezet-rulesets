rule TTP_XOR_WriteProcessMemory_b0c7 {
  strings:
    $key_b0c7 = { e7 b5 [2] d5 97 [2] d3 a2 [2] fd a2 [2] c2 be }

  condition:
    any of them
}