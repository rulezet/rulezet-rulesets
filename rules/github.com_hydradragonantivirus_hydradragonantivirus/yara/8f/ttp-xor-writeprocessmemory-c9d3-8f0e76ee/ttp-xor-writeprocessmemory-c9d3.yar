rule TTP_XOR_WriteProcessMemory_c9d3 {
  strings:
    $key_c9d3 = { 9e a1 [2] ac 83 [2] aa b6 [2] 84 b6 [2] bb aa }

  condition:
    any of them
}