rule TTP_XOR_WriteProcessMemory_92ba {
  strings:
    $key_92ba = { c5 c8 [2] f7 ea [2] f1 df [2] df df [2] e0 c3 }

  condition:
    any of them
}