rule TTP_XOR_WriteProcessMemory_1c79 {
  strings:
    $key_1c79 = { 4b 0b [2] 79 29 [2] 7f 1c [2] 51 1c [2] 6e 00 }

  condition:
    any of them
}