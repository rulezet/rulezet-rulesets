rule TTP_XOR_WriteProcessMemory_7c79 {
  strings:
    $key_7c79 = { 2b 0b [2] 19 29 [2] 1f 1c [2] 31 1c [2] 0e 00 }

  condition:
    any of them
}