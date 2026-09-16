rule TTP_XOR_WriteProcessMemory_4a33 {
  strings:
    $key_4a33 = { 1d 41 [2] 2f 63 [2] 29 56 [2] 07 56 [2] 38 4a }

  condition:
    any of them
}