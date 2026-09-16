rule TTP_XOR_WriteProcessMemory_23d3 {
  strings:
    $key_23d3 = { 74 a1 [2] 46 83 [2] 40 b6 [2] 6e b6 [2] 51 aa }

  condition:
    any of them
}