rule TTP_XOR_WriteProcessMemory_af49 {
  strings:
    $key_af49 = { f8 3b [2] ca 19 [2] cc 2c [2] e2 2c [2] dd 30 }

  condition:
    any of them
}