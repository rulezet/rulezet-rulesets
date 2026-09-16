rule TTP_XOR_WriteProcessMemory_69b3 {
  strings:
    $key_69b3 = { 3e c1 [2] 0c e3 [2] 0a d6 [2] 24 d6 [2] 1b ca }

  condition:
    any of them
}