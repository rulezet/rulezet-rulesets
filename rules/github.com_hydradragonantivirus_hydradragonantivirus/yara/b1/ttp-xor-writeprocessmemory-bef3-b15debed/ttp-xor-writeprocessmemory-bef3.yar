rule TTP_XOR_WriteProcessMemory_bef3 {
  strings:
    $key_bef3 = { e9 81 [2] db a3 [2] dd 96 [2] f3 96 [2] cc 8a }

  condition:
    any of them
}