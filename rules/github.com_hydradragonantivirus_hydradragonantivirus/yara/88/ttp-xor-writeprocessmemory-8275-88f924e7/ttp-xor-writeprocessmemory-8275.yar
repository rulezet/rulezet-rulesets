rule TTP_XOR_WriteProcessMemory_8275 {
  strings:
    $key_8275 = { d5 07 [2] e7 25 [2] e1 10 [2] cf 10 [2] f0 0c }

  condition:
    any of them
}