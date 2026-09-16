rule TTP_XOR_WriteProcessMemory_b808 {
  strings:
    $key_b808 = { ef 7a [2] dd 58 [2] db 6d [2] f5 6d [2] ca 71 }

  condition:
    any of them
}