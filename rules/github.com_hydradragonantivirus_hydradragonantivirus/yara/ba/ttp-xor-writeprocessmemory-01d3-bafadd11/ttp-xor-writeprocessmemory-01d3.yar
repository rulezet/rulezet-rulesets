rule TTP_XOR_WriteProcessMemory_01d3 {
  strings:
    $key_01d3 = { 56 a1 [2] 64 83 [2] 62 b6 [2] 4c b6 [2] 73 aa }

  condition:
    any of them
}