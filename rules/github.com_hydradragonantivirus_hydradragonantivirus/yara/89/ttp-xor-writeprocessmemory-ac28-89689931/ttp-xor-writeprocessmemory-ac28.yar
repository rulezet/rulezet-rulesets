rule TTP_XOR_WriteProcessMemory_ac28 {
  strings:
    $key_ac28 = { fb 5a [2] c9 78 [2] cf 4d [2] e1 4d [2] de 51 }

  condition:
    any of them
}