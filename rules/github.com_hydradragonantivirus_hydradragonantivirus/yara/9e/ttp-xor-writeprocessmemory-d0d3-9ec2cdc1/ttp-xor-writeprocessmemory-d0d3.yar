rule TTP_XOR_WriteProcessMemory_d0d3 {
  strings:
    $key_d0d3 = { 87 a1 [2] b5 83 [2] b3 b6 [2] 9d b6 [2] a2 aa }

  condition:
    any of them
}