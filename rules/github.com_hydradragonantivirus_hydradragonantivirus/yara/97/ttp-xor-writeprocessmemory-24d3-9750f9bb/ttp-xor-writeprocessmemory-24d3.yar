rule TTP_XOR_WriteProcessMemory_24d3 {
  strings:
    $key_24d3 = { 73 a1 [2] 41 83 [2] 47 b6 [2] 69 b6 [2] 56 aa }

  condition:
    any of them
}