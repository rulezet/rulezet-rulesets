rule TTP_XOR_WriteProcessMemory_739d {
  strings:
    $key_739d = { 24 ef [2] 16 cd [2] 10 f8 [2] 3e f8 [2] 01 e4 }

  condition:
    any of them
}