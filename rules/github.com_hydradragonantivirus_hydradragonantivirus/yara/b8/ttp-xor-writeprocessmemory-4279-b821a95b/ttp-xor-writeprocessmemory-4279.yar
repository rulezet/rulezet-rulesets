rule TTP_XOR_WriteProcessMemory_4279 {
  strings:
    $key_4279 = { 15 0b [2] 27 29 [2] 21 1c [2] 0f 1c [2] 30 00 }

  condition:
    any of them
}