rule TTP_XOR_WriteProcessMemory_7e77 {
  strings:
    $key_7e77 = { 29 05 [2] 1b 27 [2] 1d 12 [2] 33 12 [2] 0c 0e }

  condition:
    any of them
}