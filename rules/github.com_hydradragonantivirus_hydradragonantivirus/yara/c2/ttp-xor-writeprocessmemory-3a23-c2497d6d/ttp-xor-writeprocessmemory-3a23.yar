rule TTP_XOR_WriteProcessMemory_3a23 {
  strings:
    $key_3a23 = { 6d 51 [2] 5f 73 [2] 59 46 [2] 77 46 [2] 48 5a }

  condition:
    any of them
}