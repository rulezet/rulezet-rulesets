rule TTP_XOR_WriteProcessMemory_7b9d {
  strings:
    $key_7b9d = { 2c ef [2] 1e cd [2] 18 f8 [2] 36 f8 [2] 09 e4 }

  condition:
    any of them
}