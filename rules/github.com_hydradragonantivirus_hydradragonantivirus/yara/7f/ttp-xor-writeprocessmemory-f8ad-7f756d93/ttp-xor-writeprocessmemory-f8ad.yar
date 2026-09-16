rule TTP_XOR_WriteProcessMemory_f8ad {
  strings:
    $key_f8ad = { af df [2] 9d fd [2] 9b c8 [2] b5 c8 [2] 8a d4 }

  condition:
    any of them
}