rule TTP_XOR_WriteProcessMemory_86ba {
  strings:
    $key_86ba = { d1 c8 [2] e3 ea [2] e5 df [2] cb df [2] f4 c3 }

  condition:
    any of them
}