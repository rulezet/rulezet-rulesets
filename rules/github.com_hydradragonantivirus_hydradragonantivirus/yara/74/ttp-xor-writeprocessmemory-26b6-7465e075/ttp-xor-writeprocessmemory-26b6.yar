rule TTP_XOR_WriteProcessMemory_26b6 {
  strings:
    $key_26b6 = { 71 c4 [2] 43 e6 [2] 45 d3 [2] 6b d3 [2] 54 cf }

  condition:
    any of them
}