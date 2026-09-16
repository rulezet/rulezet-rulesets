rule TTP_XOR_WriteProcessMemory_0c9d {
  strings:
    $key_0c9d = { 5b ef [2] 69 cd [2] 6f f8 [2] 41 f8 [2] 7e e4 }

  condition:
    any of them
}