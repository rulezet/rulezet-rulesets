rule TTP_XOR_WriteProcessMemory_6e9d {
  strings:
    $key_6e9d = { 39 ef [2] 0b cd [2] 0d f8 [2] 23 f8 [2] 1c e4 }

  condition:
    any of them
}