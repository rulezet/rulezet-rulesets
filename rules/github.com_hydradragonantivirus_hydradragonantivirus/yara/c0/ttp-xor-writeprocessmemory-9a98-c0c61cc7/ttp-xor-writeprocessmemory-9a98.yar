rule TTP_XOR_WriteProcessMemory_9a98 {
  strings:
    $key_9a98 = { cd ea [2] ff c8 [2] f9 fd [2] d7 fd [2] e8 e1 }

  condition:
    any of them
}