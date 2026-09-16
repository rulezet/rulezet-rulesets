rule TTP_XOR_WriteProcessMemory_37d3 {
  strings:
    $key_37d3 = { 60 a1 [2] 52 83 [2] 54 b6 [2] 7a b6 [2] 45 aa }

  condition:
    any of them
}