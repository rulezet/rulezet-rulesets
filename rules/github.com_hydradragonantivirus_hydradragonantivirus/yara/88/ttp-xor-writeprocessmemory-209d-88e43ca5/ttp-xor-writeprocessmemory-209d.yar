rule TTP_XOR_WriteProcessMemory_209d {
  strings:
    $key_209d = { 77 ef [2] 45 cd [2] 43 f8 [2] 6d f8 [2] 52 e4 }

  condition:
    any of them
}