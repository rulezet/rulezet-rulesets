rule TTP_XOR_WriteProcessMemory_86ad {
  strings:
    $key_86ad = { d1 df [2] e3 fd [2] e5 c8 [2] cb c8 [2] f4 d4 }

  condition:
    any of them
}