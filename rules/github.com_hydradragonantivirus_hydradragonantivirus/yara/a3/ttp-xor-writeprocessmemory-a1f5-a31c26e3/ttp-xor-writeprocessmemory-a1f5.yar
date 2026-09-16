rule TTP_XOR_WriteProcessMemory_a1f5 {
  strings:
    $key_a1f5 = { f6 87 [2] c4 a5 [2] c2 90 [2] ec 90 [2] d3 8c }

  condition:
    any of them
}