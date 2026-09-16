rule TTP_XOR_WriteProcessMemory_b041 {
  strings:
    $key_b041 = { e7 33 [2] d5 11 [2] d3 24 [2] fd 24 [2] c2 38 }

  condition:
    any of them
}