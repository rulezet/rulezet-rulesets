rule TTP_XOR_WriteProcessMemory_34d3 {
  strings:
    $key_34d3 = { 63 a1 [2] 51 83 [2] 57 b6 [2] 79 b6 [2] 46 aa }

  condition:
    any of them
}