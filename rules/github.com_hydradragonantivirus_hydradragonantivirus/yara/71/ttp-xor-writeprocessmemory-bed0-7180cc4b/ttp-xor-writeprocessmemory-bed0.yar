rule TTP_XOR_WriteProcessMemory_bed0 {
  strings:
    $key_bed0 = { e9 a2 [2] db 80 [2] dd b5 [2] f3 b5 [2] cc a9 }

  condition:
    any of them
}