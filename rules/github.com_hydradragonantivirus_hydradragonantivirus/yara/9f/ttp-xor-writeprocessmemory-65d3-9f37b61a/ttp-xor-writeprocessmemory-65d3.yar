rule TTP_XOR_WriteProcessMemory_65d3 {
  strings:
    $key_65d3 = { 32 a1 [2] 00 83 [2] 06 b6 [2] 28 b6 [2] 17 aa }

  condition:
    any of them
}