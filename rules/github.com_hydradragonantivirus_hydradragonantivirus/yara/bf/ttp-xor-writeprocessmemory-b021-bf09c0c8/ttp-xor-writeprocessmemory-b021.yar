rule TTP_XOR_WriteProcessMemory_b021 {
  strings:
    $key_b021 = { e7 53 [2] d5 71 [2] d3 44 [2] fd 44 [2] c2 58 }

  condition:
    any of them
}