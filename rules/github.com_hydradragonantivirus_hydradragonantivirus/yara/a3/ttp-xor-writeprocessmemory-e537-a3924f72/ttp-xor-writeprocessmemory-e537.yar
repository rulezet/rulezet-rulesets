rule TTP_XOR_WriteProcessMemory_e537 {
  strings:
    $key_e537 = { b2 45 [2] 80 67 [2] 86 52 [2] a8 52 [2] 97 4e }

  condition:
    any of them
}