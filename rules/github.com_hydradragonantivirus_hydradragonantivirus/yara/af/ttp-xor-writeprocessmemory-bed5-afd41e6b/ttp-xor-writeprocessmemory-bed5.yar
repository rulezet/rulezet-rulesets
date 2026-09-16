rule TTP_XOR_WriteProcessMemory_bed5 {
  strings:
    $key_bed5 = { e9 a7 [2] db 85 [2] dd b0 [2] f3 b0 [2] cc ac }

  condition:
    any of them
}