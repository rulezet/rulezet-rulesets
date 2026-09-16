rule TTP_XOR_WriteProcessMemory_b0f1 {
  strings:
    $key_b0f1 = { e7 83 [2] d5 a1 [2] d3 94 [2] fd 94 [2] c2 88 }

  condition:
    any of them
}