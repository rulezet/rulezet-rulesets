rule TTP_XOR_WriteProcessMemory_54b6 {
  strings:
    $key_54b6 = { 03 c4 [2] 31 e6 [2] 37 d3 [2] 19 d3 [2] 26 cf }

  condition:
    any of them
}