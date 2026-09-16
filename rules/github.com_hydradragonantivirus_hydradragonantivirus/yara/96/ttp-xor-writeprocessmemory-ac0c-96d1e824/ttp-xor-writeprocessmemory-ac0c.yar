rule TTP_XOR_WriteProcessMemory_ac0c {
  strings:
    $key_ac0c = { fb 7e [2] c9 5c [2] cf 69 [2] e1 69 [2] de 75 }

  condition:
    any of them
}