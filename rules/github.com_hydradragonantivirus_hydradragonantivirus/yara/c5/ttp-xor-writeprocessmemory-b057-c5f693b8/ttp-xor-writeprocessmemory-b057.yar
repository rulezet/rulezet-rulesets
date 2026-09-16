rule TTP_XOR_WriteProcessMemory_b057 {
  strings:
    $key_b057 = { e7 25 [2] d5 07 [2] d3 32 [2] fd 32 [2] c2 2e }

  condition:
    any of them
}