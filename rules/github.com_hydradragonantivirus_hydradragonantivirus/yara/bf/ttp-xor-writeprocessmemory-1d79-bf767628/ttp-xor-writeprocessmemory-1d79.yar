rule TTP_XOR_WriteProcessMemory_1d79 {
  strings:
    $key_1d79 = { 4a 0b [2] 78 29 [2] 7e 1c [2] 50 1c [2] 6f 00 }

  condition:
    any of them
}