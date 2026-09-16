rule TTP_XOR_WriteProcessMemory_0b9d {
  strings:
    $key_0b9d = { 5c ef [2] 6e cd [2] 68 f8 [2] 46 f8 [2] 79 e4 }

  condition:
    any of them
}