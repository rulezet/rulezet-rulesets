rule TTP_XOR_WriteProcessMemory_0916 {
  strings:
    $key_0916 = { 5e 64 [2] 6c 46 [2] 6a 73 [2] 44 73 [2] 7b 6f }

  condition:
    any of them
}