rule TTP_XOR_WriteProcessMemory_a126 {
  strings:
    $key_a126 = { f6 54 [2] c4 76 [2] c2 43 [2] ec 43 [2] d3 5f }

  condition:
    any of them
}