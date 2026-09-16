rule TTP_XOR_WriteProcessMemory_bef7 {
  strings:
    $key_bef7 = { e9 85 [2] db a7 [2] dd 92 [2] f3 92 [2] cc 8e }

  condition:
    any of them
}