rule TTP_XOR_WriteProcessMemory_3c77 {
  strings:
    $key_3c77 = { 6b 05 [2] 59 27 [2] 5f 12 [2] 71 12 [2] 4e 0e }

  condition:
    any of them
}