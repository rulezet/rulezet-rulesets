rule TTP_XOR_WriteProcessMemory_9a8f {
  strings:
    $key_9a8f = { cd fd [2] ff df [2] f9 ea [2] d7 ea [2] e8 f6 }

  condition:
    any of them
}