rule TTP_XOR_WriteProcessMemory_13d3 {
  strings:
    $key_13d3 = { 44 a1 [2] 76 83 [2] 70 b6 [2] 5e b6 [2] 61 aa }

  condition:
    any of them
}