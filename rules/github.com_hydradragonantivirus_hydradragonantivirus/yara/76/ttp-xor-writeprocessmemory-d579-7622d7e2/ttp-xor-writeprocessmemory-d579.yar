rule TTP_XOR_WriteProcessMemory_d579 {
  strings:
    $key_d579 = { 82 0b [2] b0 29 [2] b6 1c [2] 98 1c [2] a7 00 }

  condition:
    any of them
}