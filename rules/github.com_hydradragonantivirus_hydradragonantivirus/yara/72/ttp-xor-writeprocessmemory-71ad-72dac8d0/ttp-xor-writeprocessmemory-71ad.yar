rule TTP_XOR_WriteProcessMemory_71ad {
  strings:
    $key_71ad = { 26 df [2] 14 fd [2] 12 c8 [2] 3c c8 [2] 03 d4 }

  condition:
    any of them
}