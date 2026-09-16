rule TTP_XOR_WriteProcessMemory_b015 {
  strings:
    $key_b015 = { e7 67 [2] d5 45 [2] d3 70 [2] fd 70 [2] c2 6c }

  condition:
    any of them
}