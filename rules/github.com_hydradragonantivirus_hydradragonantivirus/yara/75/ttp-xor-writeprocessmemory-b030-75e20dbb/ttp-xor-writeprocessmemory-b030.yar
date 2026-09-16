rule TTP_XOR_WriteProcessMemory_b030 {
  strings:
    $key_b030 = { e7 42 [2] d5 60 [2] d3 55 [2] fd 55 [2] c2 49 }

  condition:
    any of them
}