rule TTP_XOR_WriteProcessMemory_d055 {
  strings:
    $key_d055 = { 87 27 [2] b5 05 [2] b3 30 [2] 9d 30 [2] a2 2c }

  condition:
    any of them
}