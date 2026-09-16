rule TTP_XOR_WriteProcessMemory_b841 {
  strings:
    $key_b841 = { ef 33 [2] dd 11 [2] db 24 [2] f5 24 [2] ca 38 }

  condition:
    any of them
}