rule TTP_XOR_WriteProcessMemory_76bf {
  strings:
    $key_76bf = { 21 cd [2] 13 ef [2] 15 da [2] 3b da [2] 04 c6 }

  condition:
    any of them
}