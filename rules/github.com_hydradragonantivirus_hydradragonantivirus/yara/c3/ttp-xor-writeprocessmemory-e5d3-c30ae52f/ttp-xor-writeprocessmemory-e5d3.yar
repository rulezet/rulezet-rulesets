rule TTP_XOR_WriteProcessMemory_e5d3 {
  strings:
    $key_e5d3 = { b2 a1 [2] 80 83 [2] 86 b6 [2] a8 b6 [2] 97 aa }

  condition:
    any of them
}