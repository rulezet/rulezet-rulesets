rule TTP_XOR_WriteProcessMemory_b8c7 {
  strings:
    $key_b8c7 = { ef b5 [2] dd 97 [2] db a2 [2] f5 a2 [2] ca be }

  condition:
    any of them
}