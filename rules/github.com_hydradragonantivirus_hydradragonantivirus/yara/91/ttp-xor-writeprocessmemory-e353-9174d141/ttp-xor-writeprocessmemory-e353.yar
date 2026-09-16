rule TTP_XOR_WriteProcessMemory_e353 {
  strings:
    $key_e353 = { b4 21 [2] 86 03 [2] 80 36 [2] ae 36 [2] 91 2a }

  condition:
    any of them
}