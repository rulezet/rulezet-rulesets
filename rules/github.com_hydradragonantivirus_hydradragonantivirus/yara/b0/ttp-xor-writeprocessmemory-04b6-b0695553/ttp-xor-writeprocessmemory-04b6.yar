rule TTP_XOR_WriteProcessMemory_04b6 {
  strings:
    $key_04b6 = { 53 c4 [2] 61 e6 [2] 67 d3 [2] 49 d3 [2] 76 cf }

  condition:
    any of them
}