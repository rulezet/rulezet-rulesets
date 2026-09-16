rule TTP_XOR_WriteProcessMemory_16bf {
  strings:
    $key_16bf = { 41 cd [2] 73 ef [2] 75 da [2] 5b da [2] 64 c6 }

  condition:
    any of them
}