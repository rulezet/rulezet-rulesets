rule TTP_XOR_WriteProcessMemory_56b6 {
  strings:
    $key_56b6 = { 01 c4 [2] 33 e6 [2] 35 d3 [2] 1b d3 [2] 24 cf }

  condition:
    any of them
}