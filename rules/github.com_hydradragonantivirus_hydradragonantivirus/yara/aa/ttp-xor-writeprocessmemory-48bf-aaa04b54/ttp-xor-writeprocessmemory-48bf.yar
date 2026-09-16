rule TTP_XOR_WriteProcessMemory_48bf {
  strings:
    $key_48bf = { 1f cd [2] 2d ef [2] 2b da [2] 05 da [2] 3a c6 }

  condition:
    any of them
}