rule TTP_XOR_WriteProcessMemory_af46 {
  strings:
    $key_af46 = { f8 34 [2] ca 16 [2] cc 23 [2] e2 23 [2] dd 3f }

  condition:
    any of them
}