rule TTP_XOR_WriteProcessMemory_06d3 {
  strings:
    $key_06d3 = { 51 a1 [2] 63 83 [2] 65 b6 [2] 4b b6 [2] 74 aa }

  condition:
    any of them
}