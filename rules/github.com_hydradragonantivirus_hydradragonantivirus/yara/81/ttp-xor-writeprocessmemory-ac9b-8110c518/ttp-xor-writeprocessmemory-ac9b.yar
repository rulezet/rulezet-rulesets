rule TTP_XOR_WriteProcessMemory_ac9b {
  strings:
    $key_ac9b = { fb e9 [2] c9 cb [2] cf fe [2] e1 fe [2] de e2 }

  condition:
    any of them
}