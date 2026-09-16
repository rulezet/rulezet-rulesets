rule TTP_XOR_WriteProcessMemory_62b6 {
  strings:
    $key_62b6 = { 35 c4 [2] 07 e6 [2] 01 d3 [2] 2f d3 [2] 10 cf }

  condition:
    any of them
}