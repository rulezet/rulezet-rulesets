rule TTP_XOR_WriteProcessMemory_2679 {
  strings:
    $key_2679 = { 71 0b [2] 43 29 [2] 45 1c [2] 6b 1c [2] 54 00 }

  condition:
    any of them
}