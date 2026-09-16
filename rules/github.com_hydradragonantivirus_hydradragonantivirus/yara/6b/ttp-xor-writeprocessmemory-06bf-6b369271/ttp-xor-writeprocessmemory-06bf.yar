rule TTP_XOR_WriteProcessMemory_06bf {
  strings:
    $key_06bf = { 51 cd [2] 63 ef [2] 65 da [2] 4b da [2] 74 c6 }

  condition:
    any of them
}