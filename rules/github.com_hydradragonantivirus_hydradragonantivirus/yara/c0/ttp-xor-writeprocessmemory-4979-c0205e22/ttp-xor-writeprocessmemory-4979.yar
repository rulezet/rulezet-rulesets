rule TTP_XOR_WriteProcessMemory_4979 {
  strings:
    $key_4979 = { 1e 0b [2] 2c 29 [2] 2a 1c [2] 04 1c [2] 3b 00 }

  condition:
    any of them
}