rule TTP_XOR_WriteProcessMemory_e507 {
  strings:
    $key_e507 = { b2 75 [2] 80 57 [2] 86 62 [2] a8 62 [2] 97 7e }

  condition:
    any of them
}