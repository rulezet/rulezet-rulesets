rule TTP_XOR_WriteProcessMemory_449d {
  strings:
    $key_449d = { 13 ef [2] 21 cd [2] 27 f8 [2] 09 f8 [2] 36 e4 }

  condition:
    any of them
}