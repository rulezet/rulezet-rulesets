rule TTP_XOR_WriteProcessMemory_b8f2 {
  strings:
    $key_b8f2 = { ef 80 [2] dd a2 [2] db 97 [2] f5 97 [2] ca 8b }

  condition:
    any of them
}