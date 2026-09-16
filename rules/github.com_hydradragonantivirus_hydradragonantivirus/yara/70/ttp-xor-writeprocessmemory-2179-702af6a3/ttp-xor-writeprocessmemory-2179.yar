rule TTP_XOR_WriteProcessMemory_2179 {
  strings:
    $key_2179 = { 76 0b [2] 44 29 [2] 42 1c [2] 6c 1c [2] 53 00 }

  condition:
    any of them
}