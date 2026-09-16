rule TTP_XOR_WriteProcessMemory_b832 {
  strings:
    $key_b832 = { ef 40 [2] dd 62 [2] db 57 [2] f5 57 [2] ca 4b }

  condition:
    any of them
}