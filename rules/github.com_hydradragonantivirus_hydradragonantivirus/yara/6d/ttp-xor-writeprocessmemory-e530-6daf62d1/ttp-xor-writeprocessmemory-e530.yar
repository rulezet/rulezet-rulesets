rule TTP_XOR_WriteProcessMemory_e530 {
  strings:
    $key_e530 = { b2 42 [2] 80 60 [2] 86 55 [2] a8 55 [2] 97 49 }

  condition:
    any of them
}