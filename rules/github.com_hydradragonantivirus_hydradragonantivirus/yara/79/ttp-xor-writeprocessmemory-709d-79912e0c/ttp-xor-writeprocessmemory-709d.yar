rule TTP_XOR_WriteProcessMemory_709d {
  strings:
    $key_709d = { 27 ef [2] 15 cd [2] 13 f8 [2] 3d f8 [2] 02 e4 }

  condition:
    any of them
}