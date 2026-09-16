rule TTP_XOR_WriteProcessMemory_8218 {
  strings:
    $key_8218 = { d5 6a [2] e7 48 [2] e1 7d [2] cf 7d [2] f0 61 }

  condition:
    any of them
}