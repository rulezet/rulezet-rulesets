rule TTP_XOR_WriteProcessMemory_8208 {
  strings:
    $key_8208 = { d5 7a [2] e7 58 [2] e1 6d [2] cf 6d [2] f0 71 }

  condition:
    any of them
}