rule TTP_XOR_WriteProcessMemory_a187 {
  strings:
    $key_a187 = { f6 f5 [2] c4 d7 [2] c2 e2 [2] ec e2 [2] d3 fe }

  condition:
    any of them
}