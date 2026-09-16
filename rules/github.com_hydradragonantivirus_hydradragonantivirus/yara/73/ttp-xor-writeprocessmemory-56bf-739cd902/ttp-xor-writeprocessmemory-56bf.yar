rule TTP_XOR_WriteProcessMemory_56bf {
  strings:
    $key_56bf = { 01 cd [2] 33 ef [2] 35 da [2] 1b da [2] 24 c6 }

  condition:
    any of them
}