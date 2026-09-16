rule TTP_XOR_WriteProcessMemory_a9e3 {
  strings:
    $key_a9e3 = { fe 91 [2] cc b3 [2] ca 86 [2] e4 86 [2] db 9a }

  condition:
    any of them
}