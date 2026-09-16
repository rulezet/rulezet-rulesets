rule TTP_XOR_WriteProcessMemory_469d {
  strings:
    $key_469d = { 11 ef [2] 23 cd [2] 25 f8 [2] 0b f8 [2] 34 e4 }

  condition:
    any of them
}