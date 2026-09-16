rule TTP_XOR_WriteProcessMemory_e456 {
  strings:
    $key_e456 = { b3 24 [2] 81 06 [2] 87 33 [2] a9 33 [2] 96 2f }

  condition:
    any of them
}