rule TTP_XOR_WriteProcessMemory_a9d4 {
  strings:
    $key_a9d4 = { fe a6 [2] cc 84 [2] ca b1 [2] e4 b1 [2] db ad }

  condition:
    any of them
}