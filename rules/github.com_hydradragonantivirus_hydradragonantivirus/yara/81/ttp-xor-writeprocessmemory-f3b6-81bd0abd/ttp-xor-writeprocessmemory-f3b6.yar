rule TTP_XOR_WriteProcessMemory_f3b6 {
  strings:
    $key_f3b6 = { a4 c4 [2] 96 e6 [2] 90 d3 [2] be d3 [2] 81 cf }

  condition:
    any of them
}