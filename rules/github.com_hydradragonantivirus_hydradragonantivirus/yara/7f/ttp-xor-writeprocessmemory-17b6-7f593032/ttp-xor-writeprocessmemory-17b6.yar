rule TTP_XOR_WriteProcessMemory_17b6 {
  strings:
    $key_17b6 = { 40 c4 [2] 72 e6 [2] 74 d3 [2] 5a d3 [2] 65 cf }

  condition:
    any of them
}