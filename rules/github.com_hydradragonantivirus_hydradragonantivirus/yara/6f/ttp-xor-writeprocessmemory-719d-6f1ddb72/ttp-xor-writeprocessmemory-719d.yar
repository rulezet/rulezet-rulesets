rule TTP_XOR_WriteProcessMemory_719d {
  strings:
    $key_719d = { 26 ef [2] 14 cd [2] 12 f8 [2] 3c f8 [2] 03 e4 }

  condition:
    any of them
}