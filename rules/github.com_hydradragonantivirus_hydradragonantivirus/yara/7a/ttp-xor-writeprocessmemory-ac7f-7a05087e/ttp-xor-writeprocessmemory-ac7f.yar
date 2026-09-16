rule TTP_XOR_WriteProcessMemory_ac7f {
  strings:
    $key_ac7f = { fb 0d [2] c9 2f [2] cf 1a [2] e1 1a [2] de 06 }

  condition:
    any of them
}