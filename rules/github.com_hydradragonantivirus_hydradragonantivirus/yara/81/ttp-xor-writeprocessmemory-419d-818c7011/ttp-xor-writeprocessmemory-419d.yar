rule TTP_XOR_WriteProcessMemory_419d {
  strings:
    $key_419d = { 16 ef [2] 24 cd [2] 22 f8 [2] 0c f8 [2] 33 e4 }

  condition:
    any of them
}