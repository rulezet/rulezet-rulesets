rule TTP_XOR_WriteProcessMemory_e0bf {
  strings:
    $key_e0bf = { b7 cd [2] 85 ef [2] 83 da [2] ad da [2] 92 c6 }

  condition:
    any of them
}