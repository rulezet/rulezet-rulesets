rule TTP_XOR_WriteProcessMemory_d155 {
  strings:
    $key_d155 = { 86 27 [2] b4 05 [2] b2 30 [2] 9c 30 [2] a3 2c }

  condition:
    any of them
}