rule TTP_XOR_WriteProcessMemory_e6f9 {
  strings:
    $key_e6f9 = { b1 8b [2] 83 a9 [2] 85 9c [2] ab 9c [2] 94 80 }

  condition:
    any of them
}