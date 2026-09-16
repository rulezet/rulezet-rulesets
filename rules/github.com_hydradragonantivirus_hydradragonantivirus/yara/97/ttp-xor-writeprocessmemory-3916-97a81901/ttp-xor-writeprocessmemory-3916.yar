rule TTP_XOR_WriteProcessMemory_3916 {
  strings:
    $key_3916 = { 6e 64 [2] 5c 46 [2] 5a 73 [2] 74 73 [2] 4b 6f }

  condition:
    any of them
}