rule TTP_XOR_WriteProcessMemory_5c9d {
  strings:
    $key_5c9d = { 0b ef [2] 39 cd [2] 3f f8 [2] 11 f8 [2] 2e e4 }

  condition:
    any of them
}