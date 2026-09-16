rule TTP_XOR_WriteProcessMemory_e579 {
  strings:
    $key_e579 = { b2 0b [2] 80 29 [2] 86 1c [2] a8 1c [2] 97 00 }

  condition:
    any of them
}