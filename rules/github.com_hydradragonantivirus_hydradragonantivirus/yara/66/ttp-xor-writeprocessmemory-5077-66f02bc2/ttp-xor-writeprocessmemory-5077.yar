rule TTP_XOR_WriteProcessMemory_5077 {
  strings:
    $key_5077 = { 07 05 [2] 35 27 [2] 33 12 [2] 1d 12 [2] 22 0e }

  condition:
    any of them
}