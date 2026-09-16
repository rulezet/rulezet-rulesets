rule TTP_XOR_WriteProcessMemory_ac38 {
  strings:
    $key_ac38 = { fb 4a [2] c9 68 [2] cf 5d [2] e1 5d [2] de 41 }

  condition:
    any of them
}