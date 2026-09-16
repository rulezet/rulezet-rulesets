rule TTP_XOR_WriteProcessMemory_dcad {
  strings:
    $key_dcad = { 8b df [2] b9 fd [2] bf c8 [2] 91 c8 [2] ae d4 }

  condition:
    any of them
}