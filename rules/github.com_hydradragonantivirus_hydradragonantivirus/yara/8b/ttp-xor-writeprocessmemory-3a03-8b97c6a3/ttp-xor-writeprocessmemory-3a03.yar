rule TTP_XOR_WriteProcessMemory_3a03 {
  strings:
    $key_3a03 = { 6d 71 [2] 5f 53 [2] 59 66 [2] 77 66 [2] 48 7a }

  condition:
    any of them
}