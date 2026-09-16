rule TTP_XOR_WriteProcessMemory_31d3 {
  strings:
    $key_31d3 = { 66 a1 [2] 54 83 [2] 52 b6 [2] 7c b6 [2] 43 aa }

  condition:
    any of them
}