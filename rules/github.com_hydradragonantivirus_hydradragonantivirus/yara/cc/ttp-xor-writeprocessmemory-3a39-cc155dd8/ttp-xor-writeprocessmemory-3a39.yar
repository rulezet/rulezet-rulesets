rule TTP_XOR_WriteProcessMemory_3a39 {
  strings:
    $key_3a39 = { 6d 4b [2] 5f 69 [2] 59 5c [2] 77 5c [2] 48 40 }

  condition:
    any of them
}