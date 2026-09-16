rule TTP_XOR_WriteProcessMemory_e1ad {
  strings:
    $key_e1ad = { b6 df [2] 84 fd [2] 82 c8 [2] ac c8 [2] 93 d4 }

  condition:
    any of them
}