rule TTP_XOR_WriteProcessMemory_f4ad {
  strings:
    $key_f4ad = { a3 df [2] 91 fd [2] 97 c8 [2] b9 c8 [2] 86 d4 }

  condition:
    any of them
}