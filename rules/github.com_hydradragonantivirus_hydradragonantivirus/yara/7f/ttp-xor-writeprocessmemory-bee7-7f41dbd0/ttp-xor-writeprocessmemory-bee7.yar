rule TTP_XOR_WriteProcessMemory_bee7 {
  strings:
    $key_bee7 = { e9 95 [2] db b7 [2] dd 82 [2] f3 82 [2] cc 9e }

  condition:
    any of them
}