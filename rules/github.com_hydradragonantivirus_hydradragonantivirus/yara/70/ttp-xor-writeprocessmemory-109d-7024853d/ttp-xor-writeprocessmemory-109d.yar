rule TTP_XOR_WriteProcessMemory_109d {
  strings:
    $key_109d = { 47 ef [2] 75 cd [2] 73 f8 [2] 5d f8 [2] 62 e4 }

  condition:
    any of them
}