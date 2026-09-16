rule TTP_XOR_WriteProcessMemory_459d {
  strings:
    $key_459d = { 12 ef [2] 20 cd [2] 26 f8 [2] 08 f8 [2] 37 e4 }

  condition:
    any of them
}