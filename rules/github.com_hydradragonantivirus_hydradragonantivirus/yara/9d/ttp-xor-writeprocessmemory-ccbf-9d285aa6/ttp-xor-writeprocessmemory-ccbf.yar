rule TTP_XOR_WriteProcessMemory_ccbf {
  strings:
    $key_ccbf = { 9b cd [2] a9 ef [2] af da [2] 81 da [2] be c6 }

  condition:
    any of them
}