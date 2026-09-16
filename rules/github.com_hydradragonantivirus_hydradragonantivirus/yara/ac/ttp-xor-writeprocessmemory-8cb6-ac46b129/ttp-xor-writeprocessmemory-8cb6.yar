rule TTP_XOR_WriteProcessMemory_8cb6 {
  strings:
    $key_8cb6 = { db c4 [2] e9 e6 [2] ef d3 [2] c1 d3 [2] fe cf }

  condition:
    any of them
}