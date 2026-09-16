rule TTP_XOR_WriteProcessMemory_9cba {
  strings:
    $key_9cba = { cb c8 [2] f9 ea [2] ff df [2] d1 df [2] ee c3 }

  condition:
    any of them
}