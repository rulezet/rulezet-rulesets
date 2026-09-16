rule TTP_XOR_WriteProcessMemory_f8b6 {
  strings:
    $key_f8b6 = { af c4 [2] 9d e6 [2] 9b d3 [2] b5 d3 [2] 8a cf }

  condition:
    any of them
}