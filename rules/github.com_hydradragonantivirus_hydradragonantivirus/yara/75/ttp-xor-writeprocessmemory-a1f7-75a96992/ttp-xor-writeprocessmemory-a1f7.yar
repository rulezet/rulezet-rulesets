rule TTP_XOR_WriteProcessMemory_a1f7 {
  strings:
    $key_a1f7 = { f6 85 [2] c4 a7 [2] c2 92 [2] ec 92 [2] d3 8e }

  condition:
    any of them
}