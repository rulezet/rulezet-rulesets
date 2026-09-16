rule TTP_XOR_WriteProcessMemory_a4b6 {
  strings:
    $key_a4b6 = { f3 c4 [2] c1 e6 [2] c7 d3 [2] e9 d3 [2] d6 cf }

  condition:
    any of them
}