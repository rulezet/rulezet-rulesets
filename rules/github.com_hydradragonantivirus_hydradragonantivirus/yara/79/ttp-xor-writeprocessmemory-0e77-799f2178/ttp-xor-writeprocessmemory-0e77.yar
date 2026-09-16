rule TTP_XOR_WriteProcessMemory_0e77 {
  strings:
    $key_0e77 = { 59 05 [2] 6b 27 [2] 6d 12 [2] 43 12 [2] 7c 0e }

  condition:
    any of them
}