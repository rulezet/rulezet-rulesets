rule TTP_XOR_WriteProcessMemory_b044 {
  strings:
    $key_b044 = { e7 36 [2] d5 14 [2] d3 21 [2] fd 21 [2] c2 3d }

  condition:
    any of them
}