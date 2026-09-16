rule TTP_XOR_WriteProcessMemory_38b6 {
  strings:
    $key_38b6 = { 6f c4 [2] 5d e6 [2] 5b d3 [2] 75 d3 [2] 4a cf }

  condition:
    any of them
}