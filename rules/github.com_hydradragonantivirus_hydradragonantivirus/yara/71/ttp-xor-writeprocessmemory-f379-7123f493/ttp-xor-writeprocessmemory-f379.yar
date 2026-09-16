rule TTP_XOR_WriteProcessMemory_f379 {
  strings:
    $key_f379 = { a4 0b [2] 96 29 [2] 90 1c [2] be 1c [2] 81 00 }

  condition:
    any of them
}