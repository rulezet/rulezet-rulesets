rule TTP_XOR_WriteProcessMemory_43ad {
  strings:
    $key_43ad = { 14 df [2] 26 fd [2] 20 c8 [2] 0e c8 [2] 31 d4 }

  condition:
    any of them
}