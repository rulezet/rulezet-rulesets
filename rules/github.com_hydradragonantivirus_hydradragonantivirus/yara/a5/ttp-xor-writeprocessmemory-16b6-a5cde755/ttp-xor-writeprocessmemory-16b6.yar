rule TTP_XOR_WriteProcessMemory_16b6 {
  strings:
    $key_16b6 = { 41 c4 [2] 73 e6 [2] 75 d3 [2] 5b d3 [2] 64 cf }

  condition:
    any of them
}