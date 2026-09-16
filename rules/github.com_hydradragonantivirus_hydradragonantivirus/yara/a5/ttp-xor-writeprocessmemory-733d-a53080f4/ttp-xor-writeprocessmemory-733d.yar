rule TTP_XOR_WriteProcessMemory_733d {
  strings:
    $key_733d = { 24 4f [2] 16 6d [2] 10 58 [2] 3e 58 [2] 01 44 }

  condition:
    any of them
}