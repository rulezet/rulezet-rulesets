rule TTP_XOR_WriteProcessMemory_b1d3 {
  strings:
    $key_b1d3 = { e6 a1 [2] d4 83 [2] d2 b6 [2] fc b6 [2] c3 aa }

  condition:
    any of them
}