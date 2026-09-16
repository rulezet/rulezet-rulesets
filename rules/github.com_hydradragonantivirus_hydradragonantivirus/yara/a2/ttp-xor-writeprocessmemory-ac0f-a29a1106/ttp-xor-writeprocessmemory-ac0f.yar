rule TTP_XOR_WriteProcessMemory_ac0f {
  strings:
    $key_ac0f = { fb 7d [2] c9 5f [2] cf 6a [2] e1 6a [2] de 76 }

  condition:
    any of them
}