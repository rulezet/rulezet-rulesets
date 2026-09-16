rule TTP_XOR_WriteProcessMemory_ac05 {
  strings:
    $key_ac05 = { fb 77 [2] c9 55 [2] cf 60 [2] e1 60 [2] de 7c }

  condition:
    any of them
}