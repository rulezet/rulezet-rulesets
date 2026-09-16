rule TTP_XOR_WriteProcessMemory_50f4 {
  strings:
    $key_50f4 = { 07 86 [2] 35 a4 [2] 33 91 [2] 1d 91 [2] 22 8d }

  condition:
    any of them
}