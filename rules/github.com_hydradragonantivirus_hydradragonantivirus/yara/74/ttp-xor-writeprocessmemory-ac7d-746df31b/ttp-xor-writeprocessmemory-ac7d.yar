rule TTP_XOR_WriteProcessMemory_ac7d {
  strings:
    $key_ac7d = { fb 0f [2] c9 2d [2] cf 18 [2] e1 18 [2] de 04 }

  condition:
    any of them
}