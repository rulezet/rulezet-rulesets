rule TTP_XOR_WriteProcessMemory_41d3 {
  strings:
    $key_41d3 = { 16 a1 [2] 24 83 [2] 22 b6 [2] 0c b6 [2] 33 aa }

  condition:
    any of them
}