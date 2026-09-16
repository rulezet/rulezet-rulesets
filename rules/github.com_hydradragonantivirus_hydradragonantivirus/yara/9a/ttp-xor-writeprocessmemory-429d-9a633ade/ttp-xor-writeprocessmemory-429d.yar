rule TTP_XOR_WriteProcessMemory_429d {
  strings:
    $key_429d = { 15 ef [2] 27 cd [2] 21 f8 [2] 0f f8 [2] 30 e4 }

  condition:
    any of them
}