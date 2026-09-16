rule TTP_XOR_WriteProcessMemory_e6e9 {
  strings:
    $key_e6e9 = { b1 9b [2] 83 b9 [2] 85 8c [2] ab 8c [2] 94 90 }

  condition:
    any of them
}