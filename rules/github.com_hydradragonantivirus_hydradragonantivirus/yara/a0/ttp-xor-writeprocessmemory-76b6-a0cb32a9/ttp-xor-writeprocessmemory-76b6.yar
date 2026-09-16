rule TTP_XOR_WriteProcessMemory_76b6 {
  strings:
    $key_76b6 = { 21 c4 [2] 13 e6 [2] 15 d3 [2] 3b d3 [2] 04 cf }

  condition:
    any of them
}