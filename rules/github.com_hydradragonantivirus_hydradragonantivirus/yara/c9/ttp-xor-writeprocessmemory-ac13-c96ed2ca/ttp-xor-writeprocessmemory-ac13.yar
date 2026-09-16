rule TTP_XOR_WriteProcessMemory_ac13 {
  strings:
    $key_ac13 = { fb 61 [2] c9 43 [2] cf 76 [2] e1 76 [2] de 6a }

  condition:
    any of them
}