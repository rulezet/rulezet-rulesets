rule TTP_XOR_WriteProcessMemory_4c9d {
  strings:
    $key_4c9d = { 1b ef [2] 29 cd [2] 2f f8 [2] 01 f8 [2] 3e e4 }

  condition:
    any of them
}