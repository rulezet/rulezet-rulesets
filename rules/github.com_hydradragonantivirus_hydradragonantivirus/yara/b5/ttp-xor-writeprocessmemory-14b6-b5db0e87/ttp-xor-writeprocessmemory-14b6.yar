rule TTP_XOR_WriteProcessMemory_14b6 {
  strings:
    $key_14b6 = { 43 c4 [2] 71 e6 [2] 77 d3 [2] 59 d3 [2] 66 cf }

  condition:
    any of them
}