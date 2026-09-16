rule TTP_XOR_WriteProcessMemory_ac24 {
  strings:
    $key_ac24 = { fb 56 [2] c9 74 [2] cf 41 [2] e1 41 [2] de 5d }

  condition:
    any of them
}