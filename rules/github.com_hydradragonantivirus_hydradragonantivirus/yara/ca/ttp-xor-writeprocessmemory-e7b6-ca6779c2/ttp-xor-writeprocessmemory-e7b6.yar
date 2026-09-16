rule TTP_XOR_WriteProcessMemory_e7b6 {
  strings:
    $key_e7b6 = { b0 c4 [2] 82 e6 [2] 84 d3 [2] aa d3 [2] 95 cf }

  condition:
    any of them
}