rule TTP_XOR_WriteProcessMemory_20d3 {
  strings:
    $key_20d3 = { 77 a1 [2] 45 83 [2] 43 b6 [2] 6d b6 [2] 52 aa }

  condition:
    any of them
}