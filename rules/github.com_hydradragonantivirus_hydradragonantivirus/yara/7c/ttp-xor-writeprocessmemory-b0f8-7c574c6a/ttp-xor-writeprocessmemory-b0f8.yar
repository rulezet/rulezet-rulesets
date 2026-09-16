rule TTP_XOR_WriteProcessMemory_b0f8 {
  strings:
    $key_b0f8 = { e7 8a [2] d5 a8 [2] d3 9d [2] fd 9d [2] c2 81 }

  condition:
    any of them
}