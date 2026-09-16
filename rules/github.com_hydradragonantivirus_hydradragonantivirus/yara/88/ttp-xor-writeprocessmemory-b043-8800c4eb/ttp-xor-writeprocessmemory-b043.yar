rule TTP_XOR_WriteProcessMemory_b043 {
  strings:
    $key_b043 = { e7 31 [2] d5 13 [2] d3 26 [2] fd 26 [2] c2 3a }

  condition:
    any of them
}