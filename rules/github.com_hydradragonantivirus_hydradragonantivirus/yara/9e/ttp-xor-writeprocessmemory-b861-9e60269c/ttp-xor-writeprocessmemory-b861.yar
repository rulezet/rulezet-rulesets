rule TTP_XOR_WriteProcessMemory_b861 {
  strings:
    $key_b861 = { ef 13 [2] dd 31 [2] db 04 [2] f5 04 [2] ca 18 }

  condition:
    any of them
}