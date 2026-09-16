rule TTP_XOR_WriteProcessMemory_059d {
  strings:
    $key_059d = { 52 ef [2] 60 cd [2] 66 f8 [2] 48 f8 [2] 77 e4 }

  condition:
    any of them
}