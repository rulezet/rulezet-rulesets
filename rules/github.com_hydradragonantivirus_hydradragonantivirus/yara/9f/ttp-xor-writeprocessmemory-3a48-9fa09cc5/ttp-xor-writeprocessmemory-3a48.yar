rule TTP_XOR_WriteProcessMemory_3a48 {
  strings:
    $key_3a48 = { 6d 3a [2] 5f 18 [2] 59 2d [2] 77 2d [2] 48 31 }

  condition:
    any of them
}