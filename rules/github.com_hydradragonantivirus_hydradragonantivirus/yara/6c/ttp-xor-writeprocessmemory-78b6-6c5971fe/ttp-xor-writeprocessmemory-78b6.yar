rule TTP_XOR_WriteProcessMemory_78b6 {
  strings:
    $key_78b6 = { 2f c4 [2] 1d e6 [2] 1b d3 [2] 35 d3 [2] 0a cf }

  condition:
    any of them
}