rule TTP_XOR_WriteProcessMemory_6e77 {
  strings:
    $key_6e77 = { 39 05 [2] 0b 27 [2] 0d 12 [2] 23 12 [2] 1c 0e }

  condition:
    any of them
}