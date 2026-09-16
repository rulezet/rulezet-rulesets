rule TTP_XOR_WriteProcessMemory_3a18 {
  strings:
    $key_3a18 = { 6d 6a [2] 5f 48 [2] 59 7d [2] 77 7d [2] 48 61 }

  condition:
    any of them
}