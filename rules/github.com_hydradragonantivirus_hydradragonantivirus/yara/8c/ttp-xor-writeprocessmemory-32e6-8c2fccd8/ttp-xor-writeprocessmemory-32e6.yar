rule TTP_XOR_WriteProcessMemory_32e6 {
  strings:
    $key_32e6 = { 65 94 [2] 57 b6 [2] 51 83 [2] 7f 83 [2] 40 9f }

  condition:
    any of them
}