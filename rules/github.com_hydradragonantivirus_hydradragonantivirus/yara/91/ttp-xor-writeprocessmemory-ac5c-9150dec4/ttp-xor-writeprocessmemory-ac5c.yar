rule TTP_XOR_WriteProcessMemory_ac5c {
  strings:
    $key_ac5c = { fb 2e [2] c9 0c [2] cf 39 [2] e1 39 [2] de 25 }

  condition:
    any of them
}