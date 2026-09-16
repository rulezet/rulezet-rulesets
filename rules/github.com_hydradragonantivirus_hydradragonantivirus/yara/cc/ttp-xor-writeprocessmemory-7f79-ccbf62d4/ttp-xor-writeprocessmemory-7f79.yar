rule TTP_XOR_WriteProcessMemory_7f79 {
  strings:
    $key_7f79 = { 28 0b [2] 1a 29 [2] 1c 1c [2] 32 1c [2] 0d 00 }

  condition:
    any of them
}