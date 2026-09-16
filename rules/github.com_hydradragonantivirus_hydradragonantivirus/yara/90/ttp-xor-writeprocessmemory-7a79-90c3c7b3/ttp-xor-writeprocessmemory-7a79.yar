rule TTP_XOR_WriteProcessMemory_7a79 {
  strings:
    $key_7a79 = { 2d 0b [2] 1f 29 [2] 19 1c [2] 37 1c [2] 08 00 }

  condition:
    any of them
}