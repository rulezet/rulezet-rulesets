rule TTP_XOR_WriteProcessMemory_749d {
  strings:
    $key_749d = { 23 ef [2] 11 cd [2] 17 f8 [2] 39 f8 [2] 06 e4 }

  condition:
    any of them
}