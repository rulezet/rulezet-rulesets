rule TTP_XOR_WriteProcessMemory_8293 {
  strings:
    $key_8293 = { d5 e1 [2] e7 c3 [2] e1 f6 [2] cf f6 [2] f0 ea }

  condition:
    any of them
}