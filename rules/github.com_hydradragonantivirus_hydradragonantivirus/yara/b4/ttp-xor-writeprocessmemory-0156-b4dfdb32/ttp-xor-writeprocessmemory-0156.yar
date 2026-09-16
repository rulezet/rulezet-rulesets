rule TTP_XOR_WriteProcessMemory_0156 {
  strings:
    $key_0156 = { 56 24 [2] 64 06 [2] 62 33 [2] 4c 33 [2] 73 2f }

  condition:
    any of them
}