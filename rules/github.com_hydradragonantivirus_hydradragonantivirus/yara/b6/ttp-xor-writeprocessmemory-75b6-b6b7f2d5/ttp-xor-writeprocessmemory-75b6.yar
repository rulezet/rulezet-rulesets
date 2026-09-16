rule TTP_XOR_WriteProcessMemory_75b6 {
  strings:
    $key_75b6 = { 22 c4 [2] 10 e6 [2] 16 d3 [2] 38 d3 [2] 07 cf }

  condition:
    any of them
}