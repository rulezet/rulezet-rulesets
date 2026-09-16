rule TTP_XOR_WriteProcessMemory_8211 {
  strings:
    $key_8211 = { d5 63 [2] e7 41 [2] e1 74 [2] cf 74 [2] f0 68 }

  condition:
    any of them
}