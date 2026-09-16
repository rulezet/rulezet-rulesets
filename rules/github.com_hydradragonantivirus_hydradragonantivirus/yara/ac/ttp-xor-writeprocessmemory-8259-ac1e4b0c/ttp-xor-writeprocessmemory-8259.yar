rule TTP_XOR_WriteProcessMemory_8259 {
  strings:
    $key_8259 = { d5 2b [2] e7 09 [2] e1 3c [2] cf 3c [2] f0 20 }

  condition:
    any of them
}