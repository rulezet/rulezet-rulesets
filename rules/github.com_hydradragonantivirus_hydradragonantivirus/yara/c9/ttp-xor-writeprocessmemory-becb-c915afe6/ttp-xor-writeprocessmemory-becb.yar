rule TTP_XOR_WriteProcessMemory_becb {
  strings:
    $key_becb = { e9 b9 [2] db 9b [2] dd ae [2] f3 ae [2] cc b2 }

  condition:
    any of them
}