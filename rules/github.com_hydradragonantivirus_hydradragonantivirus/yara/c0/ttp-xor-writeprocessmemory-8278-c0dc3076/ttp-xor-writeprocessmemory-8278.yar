rule TTP_XOR_WriteProcessMemory_8278 {
  strings:
    $key_8278 = { d5 0a [2] e7 28 [2] e1 1d [2] cf 1d [2] f0 01 }

  condition:
    any of them
}