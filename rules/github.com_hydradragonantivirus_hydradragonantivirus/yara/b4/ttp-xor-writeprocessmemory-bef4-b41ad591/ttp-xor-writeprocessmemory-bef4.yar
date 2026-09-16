rule TTP_XOR_WriteProcessMemory_bef4 {
  strings:
    $key_bef4 = { e9 86 [2] db a4 [2] dd 91 [2] f3 91 [2] cc 8d }

  condition:
    any of them
}