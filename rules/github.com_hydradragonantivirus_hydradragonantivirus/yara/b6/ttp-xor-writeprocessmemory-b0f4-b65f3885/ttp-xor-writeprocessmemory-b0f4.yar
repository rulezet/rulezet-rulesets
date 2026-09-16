rule TTP_XOR_WriteProcessMemory_b0f4 {
  strings:
    $key_b0f4 = { e7 86 [2] d5 a4 [2] d3 91 [2] fd 91 [2] c2 8d }

  condition:
    any of them
}