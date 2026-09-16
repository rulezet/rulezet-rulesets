rule TTP_XOR_WriteProcessMemory_45d3 {
  strings:
    $key_45d3 = { 12 a1 [2] 20 83 [2] 26 b6 [2] 08 b6 [2] 37 aa }

  condition:
    any of them
}