rule TTP_XOR_WriteProcessMemory_35d3 {
  strings:
    $key_35d3 = { 62 a1 [2] 50 83 [2] 56 b6 [2] 78 b6 [2] 47 aa }

  condition:
    any of them
}