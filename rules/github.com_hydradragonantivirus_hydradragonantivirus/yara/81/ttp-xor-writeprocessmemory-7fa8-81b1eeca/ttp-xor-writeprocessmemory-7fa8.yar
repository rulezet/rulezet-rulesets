rule TTP_XOR_WriteProcessMemory_7fa8 {
  strings:
    $key_7fa8 = { 28 da [2] 1a f8 [2] 1c cd [2] 32 cd [2] 0d d1 }

  condition:
    any of them
}