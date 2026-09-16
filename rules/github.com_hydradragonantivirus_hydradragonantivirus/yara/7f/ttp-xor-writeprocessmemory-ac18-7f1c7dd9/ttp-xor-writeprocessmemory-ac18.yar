rule TTP_XOR_WriteProcessMemory_ac18 {
  strings:
    $key_ac18 = { fb 6a [2] c9 48 [2] cf 7d [2] e1 7d [2] de 61 }

  condition:
    any of them
}