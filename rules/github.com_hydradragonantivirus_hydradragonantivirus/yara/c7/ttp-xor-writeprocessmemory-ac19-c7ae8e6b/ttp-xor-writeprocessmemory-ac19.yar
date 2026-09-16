rule TTP_XOR_WriteProcessMemory_ac19 {
  strings:
    $key_ac19 = { fb 6b [2] c9 49 [2] cf 7c [2] e1 7c [2] de 60 }

  condition:
    any of them
}