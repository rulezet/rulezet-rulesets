rule TTP_XOR_WriteProcessMemory_ac69 {
  strings:
    $key_ac69 = { fb 1b [2] c9 39 [2] cf 0c [2] e1 0c [2] de 10 }

  condition:
    any of them
}