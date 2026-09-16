rule TTP_XOR_WriteProcessMemory_549d {
  strings:
    $key_549d = { 03 ef [2] 31 cd [2] 37 f8 [2] 19 f8 [2] 26 e4 }

  condition:
    any of them
}