rule TTP_XOR_WriteProcessMemory_bd94 {
  strings:
    $key_bd94 = { ea e6 [2] d8 c4 [2] de f1 [2] f0 f1 [2] cf ed }

  condition:
    any of them
}