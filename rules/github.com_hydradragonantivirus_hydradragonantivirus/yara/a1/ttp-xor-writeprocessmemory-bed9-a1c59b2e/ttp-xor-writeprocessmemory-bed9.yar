rule TTP_XOR_WriteProcessMemory_bed9 {
  strings:
    $key_bed9 = { e9 ab [2] db 89 [2] dd bc [2] f3 bc [2] cc a0 }

  condition:
    any of them
}