rule TTP_XOR_WriteProcessMemory_f9ad {
  strings:
    $key_f9ad = { ae df [2] 9c fd [2] 9a c8 [2] b4 c8 [2] 8b d4 }

  condition:
    any of them
}