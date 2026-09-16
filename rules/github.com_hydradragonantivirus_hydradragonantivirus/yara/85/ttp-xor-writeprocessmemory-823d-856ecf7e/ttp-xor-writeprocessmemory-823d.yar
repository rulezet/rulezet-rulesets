rule TTP_XOR_WriteProcessMemory_823d {
  strings:
    $key_823d = { d5 4f [2] e7 6d [2] e1 58 [2] cf 58 [2] f0 44 }

  condition:
    any of them
}