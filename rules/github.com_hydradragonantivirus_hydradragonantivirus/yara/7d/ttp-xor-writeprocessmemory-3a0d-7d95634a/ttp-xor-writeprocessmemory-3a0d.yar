rule TTP_XOR_WriteProcessMemory_3a0d {
  strings:
    $key_3a0d = { 6d 7f [2] 5f 5d [2] 59 68 [2] 77 68 [2] 48 74 }

  condition:
    any of them
}