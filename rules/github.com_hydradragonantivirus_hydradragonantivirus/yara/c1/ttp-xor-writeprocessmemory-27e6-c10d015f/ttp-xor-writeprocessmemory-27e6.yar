rule TTP_XOR_WriteProcessMemory_27e6 {
  strings:
    $key_27e6 = { 70 94 [2] 42 b6 [2] 44 83 [2] 6a 83 [2] 55 9f }

  condition:
    any of them
}