rule TTP_XOR_WriteProcessMemory_acad {
  strings:
    $key_acad = { fb df [2] c9 fd [2] cf c8 [2] e1 c8 [2] de d4 }

  condition:
    any of them
}