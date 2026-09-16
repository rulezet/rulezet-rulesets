rule TTP_XOR_WriteProcessMemory_3a17 {
  strings:
    $key_3a17 = { 6d 65 [2] 5f 47 [2] 59 72 [2] 77 72 [2] 48 6e }

  condition:
    any of them
}