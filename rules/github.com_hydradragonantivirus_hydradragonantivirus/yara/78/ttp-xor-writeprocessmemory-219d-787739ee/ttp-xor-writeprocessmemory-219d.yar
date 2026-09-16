rule TTP_XOR_WriteProcessMemory_219d {
  strings:
    $key_219d = { 76 ef [2] 44 cd [2] 42 f8 [2] 6c f8 [2] 53 e4 }

  condition:
    any of them
}