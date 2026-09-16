rule TTP_XOR_WriteProcessMemory_6f79 {
  strings:
    $key_6f79 = { 38 0b [2] 0a 29 [2] 0c 1c [2] 22 1c [2] 1d 00 }

  condition:
    any of them
}