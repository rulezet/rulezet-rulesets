rule TTP_XOR_WriteProcessMemory_08b6 {
  strings:
    $key_08b6 = { 5f c4 [2] 6d e6 [2] 6b d3 [2] 45 d3 [2] 7a cf }

  condition:
    any of them
}