rule TTP_XOR_WriteProcessMemory_8217 {
  strings:
    $key_8217 = { d5 65 [2] e7 47 [2] e1 72 [2] cf 72 [2] f0 6e }

  condition:
    any of them
}