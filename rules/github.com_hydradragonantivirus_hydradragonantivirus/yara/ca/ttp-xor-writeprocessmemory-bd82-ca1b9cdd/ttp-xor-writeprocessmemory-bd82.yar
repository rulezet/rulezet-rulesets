rule TTP_XOR_WriteProcessMemory_bd82 {
  strings:
    $key_bd82 = { ea f0 [2] d8 d2 [2] de e7 [2] f0 e7 [2] cf fb }

  condition:
    any of them
}