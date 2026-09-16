rule TTP_XOR_WriteProcessMemory_4b9d {
  strings:
    $key_4b9d = { 1c ef [2] 2e cd [2] 28 f8 [2] 06 f8 [2] 39 e4 }

  condition:
    any of them
}