rule TTP_XOR_WriteProcessMemory_6c9d {
  strings:
    $key_6c9d = { 3b ef [2] 09 cd [2] 0f f8 [2] 21 f8 [2] 1e e4 }

  condition:
    any of them
}