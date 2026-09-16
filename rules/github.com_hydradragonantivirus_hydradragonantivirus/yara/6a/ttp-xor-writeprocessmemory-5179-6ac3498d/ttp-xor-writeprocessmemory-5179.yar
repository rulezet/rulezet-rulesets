rule TTP_XOR_WriteProcessMemory_5179 {
  strings:
    $key_5179 = { 06 0b [2] 34 29 [2] 32 1c [2] 1c 1c [2] 23 00 }

  condition:
    any of them
}