rule TTP_XOR_WriteProcessMemory_3a28 {
  strings:
    $key_3a28 = { 6d 5a [2] 5f 78 [2] 59 4d [2] 77 4d [2] 48 51 }

  condition:
    any of them
}