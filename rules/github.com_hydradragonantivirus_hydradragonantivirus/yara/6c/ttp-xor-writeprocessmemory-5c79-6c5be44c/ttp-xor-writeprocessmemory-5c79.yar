rule TTP_XOR_WriteProcessMemory_5c79 {
  strings:
    $key_5c79 = { 0b 0b [2] 39 29 [2] 3f 1c [2] 11 1c [2] 2e 00 }

  condition:
    any of them
}