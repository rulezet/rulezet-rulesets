rule TTP_XOR_WriteProcessMemory_ac7a {
  strings:
    $key_ac7a = { fb 08 [2] c9 2a [2] cf 1f [2] e1 1f [2] de 03 }

  condition:
    any of them
}