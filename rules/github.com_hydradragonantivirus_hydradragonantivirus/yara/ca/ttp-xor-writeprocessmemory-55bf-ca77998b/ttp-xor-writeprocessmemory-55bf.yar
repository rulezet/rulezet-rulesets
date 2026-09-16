rule TTP_XOR_WriteProcessMemory_55bf {
  strings:
    $key_55bf = { 02 cd [2] 30 ef [2] 36 da [2] 18 da [2] 27 c6 }

  condition:
    any of them
}