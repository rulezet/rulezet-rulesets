rule TTP_XOR_WriteProcessMemory_36bf {
  strings:
    $key_36bf = { 61 cd [2] 53 ef [2] 55 da [2] 7b da [2] 44 c6 }

  condition:
    any of them
}