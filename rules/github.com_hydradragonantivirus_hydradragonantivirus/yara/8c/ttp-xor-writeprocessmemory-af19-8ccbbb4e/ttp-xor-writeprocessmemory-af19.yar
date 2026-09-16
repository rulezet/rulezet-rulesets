rule TTP_XOR_WriteProcessMemory_af19 {
  strings:
    $key_af19 = { f8 6b [2] ca 49 [2] cc 7c [2] e2 7c [2] dd 60 }

  condition:
    any of them
}