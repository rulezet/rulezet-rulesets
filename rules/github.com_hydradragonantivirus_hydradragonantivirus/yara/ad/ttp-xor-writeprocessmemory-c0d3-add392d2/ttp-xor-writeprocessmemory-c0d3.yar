rule TTP_XOR_WriteProcessMemory_c0d3 {
  strings:
    $key_c0d3 = { 97 a1 [2] a5 83 [2] a3 b6 [2] 8d b6 [2] b2 aa }

  condition:
    any of them
}