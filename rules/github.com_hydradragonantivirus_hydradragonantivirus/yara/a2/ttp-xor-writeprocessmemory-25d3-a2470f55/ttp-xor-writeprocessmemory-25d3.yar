rule TTP_XOR_WriteProcessMemory_25d3 {
  strings:
    $key_25d3 = { 72 a1 [2] 40 83 [2] 46 b6 [2] 68 b6 [2] 57 aa }

  condition:
    any of them
}