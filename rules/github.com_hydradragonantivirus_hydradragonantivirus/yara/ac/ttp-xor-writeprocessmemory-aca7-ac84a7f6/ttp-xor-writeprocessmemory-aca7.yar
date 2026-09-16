rule TTP_XOR_WriteProcessMemory_aca7 {
  strings:
    $key_aca7 = { fb d5 [2] c9 f7 [2] cf c2 [2] e1 c2 [2] de de }

  condition:
    any of them
}