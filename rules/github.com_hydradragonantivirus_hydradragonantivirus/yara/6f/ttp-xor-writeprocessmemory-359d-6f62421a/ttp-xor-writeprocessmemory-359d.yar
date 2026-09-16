rule TTP_XOR_WriteProcessMemory_359d {
  strings:
    $key_359d = { 62 ef [2] 50 cd [2] 56 f8 [2] 78 f8 [2] 47 e4 }

  condition:
    any of them
}