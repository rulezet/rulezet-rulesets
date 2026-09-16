rule TTP_XOR_WriteProcessMemory_4a77 {
  strings:
    $key_4a77 = { 1d 05 [2] 2f 27 [2] 29 12 [2] 07 12 [2] 38 0e }

  condition:
    any of them
}