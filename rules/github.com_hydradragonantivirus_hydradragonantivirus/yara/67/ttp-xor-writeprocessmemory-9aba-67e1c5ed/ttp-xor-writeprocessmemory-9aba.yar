rule TTP_XOR_WriteProcessMemory_9aba {
  strings:
    $key_9aba = { cd c8 [2] ff ea [2] f9 df [2] d7 df [2] e8 c3 }

  condition:
    any of them
}