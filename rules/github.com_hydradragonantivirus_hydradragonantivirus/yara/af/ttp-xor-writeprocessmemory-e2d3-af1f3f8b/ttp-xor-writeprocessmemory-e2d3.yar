rule TTP_XOR_WriteProcessMemory_e2d3 {
  strings:
    $key_e2d3 = { b5 a1 [2] 87 83 [2] 81 b6 [2] af b6 [2] 90 aa }

  condition:
    any of them
}