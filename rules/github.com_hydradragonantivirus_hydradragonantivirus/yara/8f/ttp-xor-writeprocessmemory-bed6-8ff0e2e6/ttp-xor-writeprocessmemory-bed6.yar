rule TTP_XOR_WriteProcessMemory_bed6 {
  strings:
    $key_bed6 = { e9 a4 [2] db 86 [2] dd b3 [2] f3 b3 [2] cc af }

  condition:
    any of them
}