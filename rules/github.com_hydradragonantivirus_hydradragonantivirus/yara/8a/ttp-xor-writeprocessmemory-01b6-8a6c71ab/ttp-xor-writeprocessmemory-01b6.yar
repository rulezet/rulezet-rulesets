rule TTP_XOR_WriteProcessMemory_01b6 {
  strings:
    $key_01b6 = { 56 c4 [2] 64 e6 [2] 62 d3 [2] 4c d3 [2] 73 cf }

  condition:
    any of them
}