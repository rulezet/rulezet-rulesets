rule TTP_XOR_WriteProcessMemory_f3ad {
  strings:
    $key_f3ad = { a4 df [2] 96 fd [2] 90 c8 [2] be c8 [2] 81 d4 }

  condition:
    any of them
}