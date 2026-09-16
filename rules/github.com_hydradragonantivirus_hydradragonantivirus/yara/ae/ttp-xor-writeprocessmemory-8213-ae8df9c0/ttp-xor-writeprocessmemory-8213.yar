rule TTP_XOR_WriteProcessMemory_8213 {
  strings:
    $key_8213 = { d5 61 [2] e7 43 [2] e1 76 [2] cf 76 [2] f0 6a }

  condition:
    any of them
}