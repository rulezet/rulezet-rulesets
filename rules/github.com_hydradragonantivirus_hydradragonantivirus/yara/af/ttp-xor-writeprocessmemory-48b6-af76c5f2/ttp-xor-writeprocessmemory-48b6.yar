rule TTP_XOR_WriteProcessMemory_48b6 {
  strings:
    $key_48b6 = { 1f c4 [2] 2d e6 [2] 2b d3 [2] 05 d3 [2] 3a cf }

  condition:
    any of them
}