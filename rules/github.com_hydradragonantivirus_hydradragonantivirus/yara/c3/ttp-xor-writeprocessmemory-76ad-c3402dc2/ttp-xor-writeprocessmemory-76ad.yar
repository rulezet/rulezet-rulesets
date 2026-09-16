rule TTP_XOR_WriteProcessMemory_76ad {
  strings:
    $key_76ad = { 21 df [2] 13 fd [2] 15 c8 [2] 3b c8 [2] 04 d4 }

  condition:
    any of them
}