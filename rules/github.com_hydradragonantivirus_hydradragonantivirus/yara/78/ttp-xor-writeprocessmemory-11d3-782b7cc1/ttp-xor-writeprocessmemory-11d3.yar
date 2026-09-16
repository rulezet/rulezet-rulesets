rule TTP_XOR_WriteProcessMemory_11d3 {
  strings:
    $key_11d3 = { 46 a1 [2] 74 83 [2] 72 b6 [2] 5c b6 [2] 63 aa }

  condition:
    any of them
}