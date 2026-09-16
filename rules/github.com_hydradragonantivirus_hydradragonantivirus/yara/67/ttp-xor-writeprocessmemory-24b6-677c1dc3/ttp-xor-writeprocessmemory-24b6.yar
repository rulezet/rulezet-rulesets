rule TTP_XOR_WriteProcessMemory_24b6 {
  strings:
    $key_24b6 = { 73 c4 [2] 41 e6 [2] 47 d3 [2] 69 d3 [2] 56 cf }

  condition:
    any of them
}