rule TTP_XOR_WriteProcessMemory_b029 {
  strings:
    $key_b029 = { e7 5b [2] d5 79 [2] d3 4c [2] fd 4c [2] c2 50 }

  condition:
    any of them
}