rule TTP_XOR_WriteProcessMemory_ac5f {
  strings:
    $key_ac5f = { fb 2d [2] c9 0f [2] cf 3a [2] e1 3a [2] de 26 }

  condition:
    any of them
}