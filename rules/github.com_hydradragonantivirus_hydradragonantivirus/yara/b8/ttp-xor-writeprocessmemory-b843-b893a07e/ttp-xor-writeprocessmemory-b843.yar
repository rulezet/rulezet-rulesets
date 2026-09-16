rule TTP_XOR_WriteProcessMemory_b843 {
  strings:
    $key_b843 = { ef 31 [2] dd 13 [2] db 26 [2] f5 26 [2] ca 3a }

  condition:
    any of them
}