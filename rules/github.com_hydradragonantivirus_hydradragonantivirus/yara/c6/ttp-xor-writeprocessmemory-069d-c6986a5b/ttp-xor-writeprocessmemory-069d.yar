rule TTP_XOR_WriteProcessMemory_069d {
  strings:
    $key_069d = { 51 ef [2] 63 cd [2] 65 f8 [2] 4b f8 [2] 74 e4 }

  condition:
    any of them
}