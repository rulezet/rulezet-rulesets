rule TTP_XOR_WriteProcessMemory_daf3 {
  strings:
    $key_daf3 = { 8d 81 [2] bf a3 [2] b9 96 [2] 97 96 [2] a8 8a }

  condition:
    any of them
}