rule TTP_XOR_WriteProcessMemory_01e6 {
  strings:
    $key_01e6 = { 56 94 [2] 64 b6 [2] 62 83 [2] 4c 83 [2] 73 9f }

  condition:
    any of them
}