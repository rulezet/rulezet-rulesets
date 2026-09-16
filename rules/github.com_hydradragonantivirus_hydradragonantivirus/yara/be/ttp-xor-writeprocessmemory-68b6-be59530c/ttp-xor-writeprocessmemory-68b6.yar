rule TTP_XOR_WriteProcessMemory_68b6 {
  strings:
    $key_68b6 = { 3f c4 [2] 0d e6 [2] 0b d3 [2] 25 d3 [2] 1a cf }

  condition:
    any of them
}