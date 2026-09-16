rule TTP_XOR_WriteProcessMemory_14d3 {
  strings:
    $key_14d3 = { 43 a1 [2] 71 83 [2] 77 b6 [2] 59 b6 [2] 66 aa }

  condition:
    any of them
}