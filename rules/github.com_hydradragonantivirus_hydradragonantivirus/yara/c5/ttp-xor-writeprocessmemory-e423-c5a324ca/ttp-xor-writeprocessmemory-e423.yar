rule TTP_XOR_WriteProcessMemory_e423 {
  strings:
    $key_e423 = { b3 51 [2] 81 73 [2] 87 46 [2] a9 46 [2] 96 5a }

  condition:
    any of them
}