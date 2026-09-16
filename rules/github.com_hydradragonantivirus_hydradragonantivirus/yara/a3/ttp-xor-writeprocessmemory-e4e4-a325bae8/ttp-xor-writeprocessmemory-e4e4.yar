rule TTP_XOR_WriteProcessMemory_e4e4 {
  strings:
    $key_e4e4 = { b3 96 [2] 81 b4 [2] 87 81 [2] a9 81 [2] 96 9d }

  condition:
    any of them
}