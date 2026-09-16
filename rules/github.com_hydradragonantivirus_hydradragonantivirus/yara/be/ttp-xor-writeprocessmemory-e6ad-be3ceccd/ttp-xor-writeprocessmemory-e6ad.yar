rule TTP_XOR_WriteProcessMemory_e6ad {
  strings:
    $key_e6ad = { b1 df [2] 83 fd [2] 85 c8 [2] ab c8 [2] 94 d4 }

  condition:
    any of them
}