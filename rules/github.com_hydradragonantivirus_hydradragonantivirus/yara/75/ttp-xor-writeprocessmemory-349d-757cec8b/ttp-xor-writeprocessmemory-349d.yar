rule TTP_XOR_WriteProcessMemory_349d {
  strings:
    $key_349d = { 63 ef [2] 51 cd [2] 57 f8 [2] 79 f8 [2] 46 e4 }

  condition:
    any of them
}