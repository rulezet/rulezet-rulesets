rule TTP_XOR_WriteProcessMemory_47d3 {
  strings:
    $key_47d3 = { 10 a1 [2] 22 83 [2] 24 b6 [2] 0a b6 [2] 35 aa }

  condition:
    any of them
}