rule TTP_XOR_WriteProcessMemory_35b6 {
  strings:
    $key_35b6 = { 62 c4 [2] 50 e6 [2] 56 d3 [2] 78 d3 [2] 47 cf }

  condition:
    any of them
}