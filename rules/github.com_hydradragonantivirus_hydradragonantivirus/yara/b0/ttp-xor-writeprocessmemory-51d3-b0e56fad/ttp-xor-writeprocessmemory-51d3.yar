rule TTP_XOR_WriteProcessMemory_51d3 {
  strings:
    $key_51d3 = { 06 a1 [2] 34 83 [2] 32 b6 [2] 1c b6 [2] 23 aa }

  condition:
    any of them
}