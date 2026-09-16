rule TTP_XOR_WriteProcessMemory_3a38 {
  strings:
    $key_3a38 = { 6d 4a [2] 5f 68 [2] 59 5d [2] 77 5d [2] 48 41 }

  condition:
    any of them
}