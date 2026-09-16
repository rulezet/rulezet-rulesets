rule TTP_XOR_WriteProcessMemory_3a7d {
  strings:
    $key_3a7d = { 6d 0f [2] 5f 2d [2] 59 18 [2] 77 18 [2] 48 04 }

  condition:
    any of them
}