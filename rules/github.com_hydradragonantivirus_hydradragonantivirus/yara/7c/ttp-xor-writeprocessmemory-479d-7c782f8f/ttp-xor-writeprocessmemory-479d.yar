rule TTP_XOR_WriteProcessMemory_479d {
  strings:
    $key_479d = { 10 ef [2] 22 cd [2] 24 f8 [2] 0a f8 [2] 35 e4 }

  condition:
    any of them
}