rule TTP_XOR_WriteProcessMemory_b023 {
  strings:
    $key_b023 = { e7 51 [2] d5 73 [2] d3 46 [2] fd 46 [2] c2 5a }

  condition:
    any of them
}