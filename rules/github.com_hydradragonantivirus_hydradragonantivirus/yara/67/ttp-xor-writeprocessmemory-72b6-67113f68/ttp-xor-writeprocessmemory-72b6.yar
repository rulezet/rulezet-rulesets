rule TTP_XOR_WriteProcessMemory_72b6 {
  strings:
    $key_72b6 = { 25 c4 [2] 17 e6 [2] 11 d3 [2] 3f d3 [2] 00 cf }

  condition:
    any of them
}