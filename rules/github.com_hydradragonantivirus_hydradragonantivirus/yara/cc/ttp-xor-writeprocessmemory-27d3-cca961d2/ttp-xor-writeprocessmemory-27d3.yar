rule TTP_XOR_WriteProcessMemory_27d3 {
  strings:
    $key_27d3 = { 70 a1 [2] 42 83 [2] 44 b6 [2] 6a b6 [2] 55 aa }

  condition:
    any of them
}