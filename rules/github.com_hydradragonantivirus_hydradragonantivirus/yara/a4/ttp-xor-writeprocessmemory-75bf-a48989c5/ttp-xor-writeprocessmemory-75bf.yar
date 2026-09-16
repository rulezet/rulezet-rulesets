rule TTP_XOR_WriteProcessMemory_75bf {
  strings:
    $key_75bf = { 22 cd [2] 10 ef [2] 16 da [2] 38 da [2] 07 c6 }

  condition:
    any of them
}