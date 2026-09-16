rule TTP_XOR_WriteProcessMemory_dae6 {
  strings:
    $key_dae6 = { 8d 94 [2] bf b6 [2] b9 83 [2] 97 83 [2] a8 9f }

  condition:
    any of them
}