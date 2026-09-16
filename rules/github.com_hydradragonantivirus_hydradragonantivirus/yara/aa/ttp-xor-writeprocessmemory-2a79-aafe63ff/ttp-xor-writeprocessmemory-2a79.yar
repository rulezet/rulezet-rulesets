rule TTP_XOR_WriteProcessMemory_2a79 {
  strings:
    $key_2a79 = { 7d 0b [2] 4f 29 [2] 49 1c [2] 67 1c [2] 58 00 }

  condition:
    any of them
}