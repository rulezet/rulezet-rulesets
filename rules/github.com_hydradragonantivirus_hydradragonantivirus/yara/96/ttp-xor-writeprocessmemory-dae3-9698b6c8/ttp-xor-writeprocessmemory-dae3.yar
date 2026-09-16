rule TTP_XOR_WriteProcessMemory_dae3 {
  strings:
    $key_dae3 = { 8d 91 [2] bf b3 [2] b9 86 [2] 97 86 [2] a8 9a }

  condition:
    any of them
}