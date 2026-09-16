rule TTP_XOR_WriteProcessMemory_b0d7 {
  strings:
    $key_b0d7 = { e7 a5 [2] d5 87 [2] d3 b2 [2] fd b2 [2] c2 ae }

  condition:
    any of them
}