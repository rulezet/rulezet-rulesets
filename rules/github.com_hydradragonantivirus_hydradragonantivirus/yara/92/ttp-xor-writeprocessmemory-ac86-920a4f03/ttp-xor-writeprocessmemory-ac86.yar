rule TTP_XOR_WriteProcessMemory_ac86 {
  strings:
    $key_ac86 = { fb f4 [2] c9 d6 [2] cf e3 [2] e1 e3 [2] de ff }

  condition:
    any of them
}