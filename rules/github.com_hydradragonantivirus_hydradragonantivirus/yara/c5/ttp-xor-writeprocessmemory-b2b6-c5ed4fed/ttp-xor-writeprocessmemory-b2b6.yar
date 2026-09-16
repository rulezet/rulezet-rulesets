rule TTP_XOR_WriteProcessMemory_b2b6 {
  strings:
    $key_b2b6 = { e5 c4 [2] d7 e6 [2] d1 d3 [2] ff d3 [2] c0 cf }

  condition:
    any of them
}