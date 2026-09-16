rule TTP_XOR_WriteProcessMemory_529d {
  strings:
    $key_529d = { 05 ef [2] 37 cd [2] 31 f8 [2] 1f f8 [2] 20 e4 }

  condition:
    any of them
}