rule TTP_XOR_WriteProcessMemory_e3ad {
  strings:
    $key_e3ad = { b4 df [2] 86 fd [2] 80 c8 [2] ae c8 [2] 91 d4 }

  condition:
    any of them
}