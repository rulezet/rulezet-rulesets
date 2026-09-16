rule TTP_XOR_WriteProcessMemory_74d3 {
  strings:
    $key_74d3 = { 23 a1 [2] 11 83 [2] 17 b6 [2] 39 b6 [2] 06 aa }

  condition:
    any of them
}