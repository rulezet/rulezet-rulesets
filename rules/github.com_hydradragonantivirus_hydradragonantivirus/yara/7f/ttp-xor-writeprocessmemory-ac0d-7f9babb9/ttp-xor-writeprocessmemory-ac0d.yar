rule TTP_XOR_WriteProcessMemory_ac0d {
  strings:
    $key_ac0d = { fb 7f [2] c9 5d [2] cf 68 [2] e1 68 [2] de 74 }

  condition:
    any of them
}