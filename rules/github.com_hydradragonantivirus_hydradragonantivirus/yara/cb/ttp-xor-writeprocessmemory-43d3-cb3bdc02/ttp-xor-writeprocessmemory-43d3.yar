rule TTP_XOR_WriteProcessMemory_43d3 {
  strings:
    $key_43d3 = { 14 a1 [2] 26 83 [2] 20 b6 [2] 0e b6 [2] 31 aa }

  condition:
    any of them
}