rule TTP_XOR_WriteProcessMemory_01ad {
  strings:
    $key_01ad = { 56 df [2] 64 fd [2] 62 c8 [2] 4c c8 [2] 73 d4 }

  condition:
    any of them
}