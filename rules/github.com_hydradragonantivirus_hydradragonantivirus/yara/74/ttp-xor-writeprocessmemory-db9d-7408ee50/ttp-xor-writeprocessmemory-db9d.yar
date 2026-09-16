rule TTP_XOR_WriteProcessMemory_db9d {
  strings:
    $key_db9d = { 8c ef [2] be cd [2] b8 f8 [2] 96 f8 [2] a9 e4 }

  condition:
    any of them
}