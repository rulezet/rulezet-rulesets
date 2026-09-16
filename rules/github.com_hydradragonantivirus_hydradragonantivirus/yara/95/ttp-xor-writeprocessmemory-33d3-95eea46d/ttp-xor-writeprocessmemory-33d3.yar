rule TTP_XOR_WriteProcessMemory_33d3 {
  strings:
    $key_33d3 = { 64 a1 [2] 56 83 [2] 50 b6 [2] 7e b6 [2] 41 aa }

  condition:
    any of them
}