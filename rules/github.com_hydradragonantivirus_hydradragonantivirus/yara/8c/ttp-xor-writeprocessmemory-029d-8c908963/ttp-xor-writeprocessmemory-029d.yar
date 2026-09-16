rule TTP_XOR_WriteProcessMemory_029d {
  strings:
    $key_029d = { 55 ef [2] 67 cd [2] 61 f8 [2] 4f f8 [2] 70 e4 }

  condition:
    any of them
}