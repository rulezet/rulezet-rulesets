rule TTP_XOR_WriteProcessMemory_828c {
  strings:
    $key_828c = { d5 fe [2] e7 dc [2] e1 e9 [2] cf e9 [2] f0 f5 }

  condition:
    any of them
}