rule TTP_XOR_WriteProcessMemory_3a4d {
  strings:
    $key_3a4d = { 6d 3f [2] 5f 1d [2] 59 28 [2] 77 28 [2] 48 34 }

  condition:
    any of them
}