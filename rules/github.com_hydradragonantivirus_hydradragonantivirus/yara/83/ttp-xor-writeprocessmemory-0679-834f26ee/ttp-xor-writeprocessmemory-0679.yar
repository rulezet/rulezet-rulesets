rule TTP_XOR_WriteProcessMemory_0679 {
  strings:
    $key_0679 = { 51 0b [2] 63 29 [2] 65 1c [2] 4b 1c [2] 74 00 }

  condition:
    any of them
}