rule TTP_XOR_WriteProcessMemory_b803 {
  strings:
    $key_b803 = { ef 71 [2] dd 53 [2] db 66 [2] f5 66 [2] ca 7a }

  condition:
    any of them
}