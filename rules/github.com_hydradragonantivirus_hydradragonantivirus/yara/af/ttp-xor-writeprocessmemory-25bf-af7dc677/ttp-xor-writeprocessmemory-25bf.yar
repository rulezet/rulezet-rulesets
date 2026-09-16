rule TTP_XOR_WriteProcessMemory_25bf {
  strings:
    $key_25bf = { 72 cd [2] 40 ef [2] 46 da [2] 68 da [2] 57 c6 }

  condition:
    any of them
}