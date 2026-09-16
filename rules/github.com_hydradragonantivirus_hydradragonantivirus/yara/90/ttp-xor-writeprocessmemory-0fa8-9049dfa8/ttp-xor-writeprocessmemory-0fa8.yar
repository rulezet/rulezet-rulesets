rule TTP_XOR_WriteProcessMemory_0fa8 {
  strings:
    $key_0fa8 = { 58 da [2] 6a f8 [2] 6c cd [2] 42 cd [2] 7d d1 }

  condition:
    any of them
}