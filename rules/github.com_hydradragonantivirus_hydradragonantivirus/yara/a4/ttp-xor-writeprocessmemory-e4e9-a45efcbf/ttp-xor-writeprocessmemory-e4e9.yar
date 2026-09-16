rule TTP_XOR_WriteProcessMemory_e4e9 {
  strings:
    $key_e4e9 = { b3 9b [2] 81 b9 [2] 87 8c [2] a9 8c [2] 96 90 }

  condition:
    any of them
}