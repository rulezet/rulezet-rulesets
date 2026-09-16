rule TTP_XOR_WriteProcessMemory_e2ad {
  strings:
    $key_e2ad = { b5 df [2] 87 fd [2] 81 c8 [2] af c8 [2] 90 d4 }

  condition:
    any of them
}