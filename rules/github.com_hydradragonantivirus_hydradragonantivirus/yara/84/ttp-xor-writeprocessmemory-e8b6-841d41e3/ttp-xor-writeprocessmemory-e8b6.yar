rule TTP_XOR_WriteProcessMemory_e8b6 {
  strings:
    $key_e8b6 = { bf c4 [2] 8d e6 [2] 8b d3 [2] a5 d3 [2] 9a cf }

  condition:
    any of them
}