rule TTP_XOR_WriteProcessMemory_bd14 {
  strings:
    $key_bd14 = { ea 66 [2] d8 44 [2] de 71 [2] f0 71 [2] cf 6d }

  condition:
    any of them
}