rule TTP_XOR_WriteProcessMemory_beb4 {
  strings:
    $key_beb4 = { e9 c6 [2] db e4 [2] dd d1 [2] f3 d1 [2] cc cd }

  condition:
    any of them
}