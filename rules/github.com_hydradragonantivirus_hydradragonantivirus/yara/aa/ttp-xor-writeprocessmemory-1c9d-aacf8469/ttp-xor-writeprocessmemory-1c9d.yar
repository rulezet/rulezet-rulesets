rule TTP_XOR_WriteProcessMemory_1c9d {
  strings:
    $key_1c9d = { 4b ef [2] 79 cd [2] 7f f8 [2] 51 f8 [2] 6e e4 }

  condition:
    any of them
}