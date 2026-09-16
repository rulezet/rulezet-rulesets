rule TTP_XOR_WriteProcessMemory_c455 {
  strings:
    $key_c455 = { 93 27 [2] a1 05 [2] a7 30 [2] 89 30 [2] b6 2c }

  condition:
    any of them
}