rule TTP_XOR_WriteProcessMemory_3a37 {
  strings:
    $key_3a37 = { 6d 45 [2] 5f 67 [2] 59 52 [2] 77 52 [2] 48 4e }

  condition:
    any of them
}