rule TTP_XOR_WriteProcessMemory_ff79 {
  strings:
    $key_ff79 = { a8 0b [2] 9a 29 [2] 9c 1c [2] b2 1c [2] 8d 00 }

  condition:
    any of them
}