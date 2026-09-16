rule TTP_XOR_WriteProcessMemory_afed {
  strings:
    $key_afed = { f8 9f [2] ca bd [2] cc 88 [2] e2 88 [2] dd 94 }

  condition:
    any of them
}