rule TTP_XOR_WriteProcessMemory_bd8c {
  strings:
    $key_bd8c = { ea fe [2] d8 dc [2] de e9 [2] f0 e9 [2] cf f5 }

  condition:
    any of them
}