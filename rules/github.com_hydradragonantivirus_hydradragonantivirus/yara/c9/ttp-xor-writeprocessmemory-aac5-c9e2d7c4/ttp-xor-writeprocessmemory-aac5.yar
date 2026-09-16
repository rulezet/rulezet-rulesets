rule TTP_XOR_WriteProcessMemory_aac5 {
  strings:
    $key_aac5 = { fd b7 [2] cf 95 [2] c9 a0 [2] e7 a0 [2] d8 bc }

  condition:
    any of them
}