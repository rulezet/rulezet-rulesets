rule TTP_XOR_WriteProcessMemory_cdad {
  strings:
    $key_cdad = { 9a df [2] a8 fd [2] ae c8 [2] 80 c8 [2] bf d4 }

  condition:
    any of them
}