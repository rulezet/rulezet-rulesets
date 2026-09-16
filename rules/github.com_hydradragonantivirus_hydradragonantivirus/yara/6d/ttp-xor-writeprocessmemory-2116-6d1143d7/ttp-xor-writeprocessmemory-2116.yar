rule TTP_XOR_WriteProcessMemory_2116 {
  strings:
    $key_2116 = { 76 64 [2] 44 46 [2] 42 73 [2] 6c 73 [2] 53 6f }

  condition:
    any of them
}