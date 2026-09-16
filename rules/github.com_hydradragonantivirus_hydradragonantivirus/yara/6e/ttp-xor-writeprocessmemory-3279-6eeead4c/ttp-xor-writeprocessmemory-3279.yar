rule TTP_XOR_WriteProcessMemory_3279 {
  strings:
    $key_3279 = { 65 0b [2] 57 29 [2] 51 1c [2] 7f 1c [2] 40 00 }

  condition:
    any of them
}