rule TTP_XOR_WriteProcessMemory_07b6 {
  strings:
    $key_07b6 = { 50 c4 [2] 62 e6 [2] 64 d3 [2] 4a d3 [2] 75 cf }

  condition:
    any of them
}