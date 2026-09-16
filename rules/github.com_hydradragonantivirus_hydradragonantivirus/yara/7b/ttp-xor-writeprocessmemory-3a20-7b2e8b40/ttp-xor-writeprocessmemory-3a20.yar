rule TTP_XOR_WriteProcessMemory_3a20 {
  strings:
    $key_3a20 = { 6d 52 [2] 5f 70 [2] 59 45 [2] 77 45 [2] 48 59 }

  condition:
    any of them
}