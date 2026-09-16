rule TTP_XOR_WriteProcessMemory_6b9d {
  strings:
    $key_6b9d = { 3c ef [2] 0e cd [2] 08 f8 [2] 26 f8 [2] 19 e4 }

  condition:
    any of them
}