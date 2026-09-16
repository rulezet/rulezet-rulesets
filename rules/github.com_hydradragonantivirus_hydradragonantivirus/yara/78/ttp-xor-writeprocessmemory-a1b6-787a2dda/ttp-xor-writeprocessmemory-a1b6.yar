rule TTP_XOR_WriteProcessMemory_a1b6 {
  strings:
    $key_a1b6 = { f6 c4 [2] c4 e6 [2] c2 d3 [2] ec d3 [2] d3 cf }

  condition:
    any of them
}