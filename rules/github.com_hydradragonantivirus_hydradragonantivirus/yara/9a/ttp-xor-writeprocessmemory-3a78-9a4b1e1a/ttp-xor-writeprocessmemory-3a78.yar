rule TTP_XOR_WriteProcessMemory_3a78 {
  strings:
    $key_3a78 = { 6d 0a [2] 5f 28 [2] 59 1d [2] 77 1d [2] 48 01 }

  condition:
    any of them
}