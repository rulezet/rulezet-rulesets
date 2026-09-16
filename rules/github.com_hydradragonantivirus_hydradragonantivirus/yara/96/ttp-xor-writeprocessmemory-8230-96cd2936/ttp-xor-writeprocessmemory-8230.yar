rule TTP_XOR_WriteProcessMemory_8230 {
  strings:
    $key_8230 = { d5 42 [2] e7 60 [2] e1 55 [2] cf 55 [2] f0 49 }

  condition:
    any of them
}