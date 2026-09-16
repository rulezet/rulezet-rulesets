rule TTP_XOR_WriteProcessMemory_12d3 {
  strings:
    $key_12d3 = { 45 a1 [2] 77 83 [2] 71 b6 [2] 5f b6 [2] 60 aa }

  condition:
    any of them
}